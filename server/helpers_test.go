// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/require"
)

// fakeAPI is the part of the plugin API the app uses, in memory. Any other method panics (the embedded API is nil),
// which shows an unexpected call.
type fakeAPI struct {
	plugin.API

	mu       sync.Mutex
	kv       map[string][]byte
	posts    map[string]*model.Post
	created  []*model.Post
	updated  []*model.Post
	channels map[string]*model.Channel
	// byName maps "team/channel" to a channel ID.
	byName         map[string]string
	channelMembers map[string]map[string]*model.ChannelMember
	teamMembers    map[string]map[string]*model.TeamMember
	sysadmins      map[string]bool
	cannotPost     map[string]bool
	users          map[string]*model.User
	logs           []string
	dialogs        []model.OpenDialogRequest
	tools          []*model.AIToolDefinition
	registerCalls  int
	config         *configuration
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		kv:             map[string][]byte{},
		posts:          map[string]*model.Post{},
		channels:       map[string]*model.Channel{},
		byName:         map[string]string{},
		channelMembers: map[string]map[string]*model.ChannelMember{},
		teamMembers:    map[string]map[string]*model.TeamMember{},
		sysadmins:      map[string]bool{},
		cannotPost:     map[string]bool{},
		users:          map[string]*model.User{},
	}
}

func notFound(where string) *model.AppError {
	return model.NewAppError(where, "not_found", nil, "", http.StatusNotFound)
}

func (f *fakeAPI) LoadPluginConfiguration(dest any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.config != nil {
		*(dest.(*configuration)) = *f.config
	}
	return nil
}

func (f *fakeAPI) EnsureBotUser(*model.Bot) (string, error) { return botUserID, nil }

func (f *fakeAPI) RegisterAITools(tools []*model.AIToolDefinition) *model.AppError {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registerCalls++
	f.tools = tools
	return nil
}

func (f *fakeAPI) KVGet(key string) ([]byte, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.kv[key]; ok {
		return bytes.Clone(v), nil
	}
	return nil, nil
}

func (f *fakeAPI) KVSetWithOptions(key string, value []byte, _ model.PluginKVSetOptions) (bool, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if value == nil {
		delete(f.kv, key)
	} else {
		f.kv[key] = bytes.Clone(value)
	}
	return true, nil
}

func (f *fakeAPI) CreatePost(post *model.Post) (*model.Post, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	saved := post.Clone()
	saved.Id = model.NewId()
	f.posts[saved.Id] = saved
	f.created = append(f.created, saved)
	return saved.Clone(), nil
}

func (f *fakeAPI) UpdatePost(post *model.Post) (*model.Post, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.posts[post.Id]; !ok {
		return nil, notFound("UpdatePost")
	}
	saved := post.Clone()
	f.posts[saved.Id] = saved
	f.updated = append(f.updated, saved)
	return saved.Clone(), nil
}

func (f *fakeAPI) GetPost(postID string) (*model.Post, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.posts[postID]; ok {
		return p.Clone(), nil
	}
	return nil, notFound("GetPost")
}

func (f *fakeAPI) GetChannel(channelID string) (*model.Channel, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.channels[channelID]; ok {
		cc := *c
		return &cc, nil
	}
	return nil, notFound("GetChannel")
}

func (f *fakeAPI) GetChannelByNameForTeamName(team, channel string, _ bool) (*model.Channel, *model.AppError) {
	f.mu.Lock()
	id, ok := f.byName[team+"/"+channel]
	f.mu.Unlock()
	if !ok {
		return nil, notFound("GetChannelByNameForTeamName")
	}
	return f.GetChannel(id)
}

func (f *fakeAPI) GetChannelMember(channelID, userID string) (*model.ChannelMember, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.channelMembers[channelID][userID]; ok {
		mm := *m
		return &mm, nil
	}
	return nil, notFound("GetChannelMember")
}

func (f *fakeAPI) GetTeamMember(teamID, userID string) (*model.TeamMember, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.teamMembers[teamID][userID]; ok {
		mm := *m
		return &mm, nil
	}
	return nil, notFound("GetTeamMember")
}

func (f *fakeAPI) HasPermissionTo(userID string, permission *model.Permission) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return permission.Id == model.PermissionManageSystem.Id && f.sysadmins[userID]
}

func (f *fakeAPI) HasPermissionToChannel(userID, channelID string, permission *model.Permission) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	channel := f.channels[channelID]
	if channel == nil {
		return false
	}
	_, member := f.channelMembers[channelID][userID]
	switch permission.Id {
	case model.PermissionReadChannelContent.Id:
		if member {
			return true
		}
		_, inTeam := f.teamMembers[channel.TeamId][userID]
		return channel.Type == model.ChannelTypeOpen && inTeam
	case model.PermissionCreatePost.Id:
		return member && !f.cannotPost[userID]
	}
	return false
}

func (f *fakeAPI) GetUser(userID string) (*model.User, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[userID]; ok {
		uu := *u
		return &uu, nil
	}
	return nil, notFound("GetUser")
}

func (f *fakeAPI) OpenInteractiveDialog(dialog model.OpenDialogRequest) *model.AppError {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialogs = append(f.dialogs, dialog)
	return nil
}

func (f *fakeAPI) log(level, msg string, keyValuePairs ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, level+" "+msg+" "+fmt.Sprint(keyValuePairs...))
}

func (f *fakeAPI) LogDebug(msg string, kv ...any) { f.log("debug", msg, kv...) }
func (f *fakeAPI) LogInfo(msg string, kv ...any)  { f.log("info", msg, kv...) }
func (f *fakeAPI) LogWarn(msg string, kv ...any)  { f.log("warn", msg, kv...) }
func (f *fakeAPI) LogError(msg string, kv ...any) { f.log("error", msg, kv...) }

func (f *fakeAPI) allLogs() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

func (f *fakeAPI) createdPosts() []*model.Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*model.Post(nil), f.created...)
}

func (f *fakeAPI) updatedPosts() []*model.Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*model.Post(nil), f.updated...)
}

func (f *fakeAPI) post(id string) *model.Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts[id]
}

// The people and places of the tests.
var (
	botUserID     = model.NewId()
	teamID        = model.NewId()
	alertsChannel = model.NewId()
	dbChannel     = model.NewId()
	otherChannel  = model.NewId()

	channelAdmin = model.NewId()
	teamAdmin    = model.NewId()
	sysadmin     = model.NewId()
	member       = model.NewId()
	readOnly     = model.NewId()
	outsider     = model.NewId()
	dbAdmin      = model.NewId()
)

const (
	testSecret      = "s3cret-webhook-token-0123456789abcdef"
	testBearerToken = "bearer-token-zyxwvutsrqponm"
	testPassword    = "basic-password-qwertyuiop"
)

// fakeAM is a fake Alertmanager: it records the requests and answers them.
type fakeAM struct {
	mu       sync.Mutex
	server   *httptest.Server
	requests []amRequest
	alerts   []amAlert
	silences []amSilence
	// failCreate makes POST /api/v2/silences fail.
	failCreate bool
	nextID     int
}

type amRequest struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   string
	Auth   string
}

func newFakeAM(t *testing.T) *fakeAM {
	am := &fakeAM{}
	am.server = httptest.NewServer(http.HandlerFunc(am.serve))
	t.Cleanup(am.server.Close)
	return am
}

func (am *fakeAM) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	am.mu.Lock()
	defer am.mu.Unlock()
	am.requests = append(am.requests, amRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body), Auth: r.Header.Get("Authorization")})
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/alerts":
		_ = json.NewEncoder(w).Encode(am.alerts)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/silences":
		_ = json.NewEncoder(w).Encode(am.silences)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/silences":
		if am.failCreate {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`"silence invalid"`))
			return
		}
		var s amPostableSilence
		_ = json.Unmarshal(body, &s)
		id := s.ID
		if id == "" {
			am.nextID++
			id = fmt.Sprintf("00000000-0000-0000-0000-%012d", am.nextID)
		}
		am.silences = append(am.silences, amSilence{ID: id, Status: amSilenceStatus{State: "active"}, Matchers: s.Matchers, StartsAt: s.StartsAt, EndsAt: s.EndsAt, CreatedBy: s.CreatedBy, Comment: s.Comment})
		_ = json.NewEncoder(w).Encode(map[string]string{"silenceID": id})
	case strings.HasPrefix(r.URL.Path, "/api/v2/silence/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v2/silence/")
		for n := range am.silences {
			if am.silences[n].ID == id {
				if r.Method == http.MethodDelete {
					am.silences[n].Status.State = "expired"
					return
				}
				_ = json.NewEncoder(w).Encode(am.silences[n])
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (am *fakeAM) calls() []amRequest {
	am.mu.Lock()
	defer am.mu.Unlock()
	return append([]amRequest(nil), am.requests...)
}

// writes gives the requests that change something.
func (am *fakeAM) writes() []amRequest {
	var out []amRequest
	for _, r := range am.calls() {
		if r.Method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

type testEnv struct {
	t   *testing.T
	p   *Plugin
	api *fakeAPI
	am  *fakeAM
	now time.Time
}

type envOption func(*configuration)

func withPermission(mode string) envOption {
	return func(c *configuration) { c.SilencePermission = mode }
}

func withSeverityNone() envOption {
	return func(c *configuration) { c.PostSeverityNone = true }
}

func newTestEnv(t *testing.T, options ...envOption) *testEnv {
	t.Helper()
	api := newFakeAPI()
	am := newFakeAM(t)
	env := &testEnv{t: t, api: api, am: am, now: time.Date(2026, 10, 24, 18, 0, 0, 0, time.UTC)}

	api.channels[alertsChannel] = &model.Channel{Id: alertsChannel, TeamId: teamID, Name: "alerts", Type: model.ChannelTypeOpen}
	api.channels[dbChannel] = &model.Channel{Id: dbChannel, TeamId: teamID, Name: "db-alerts", Type: model.ChannelTypePrivate}
	api.channels[otherChannel] = &model.Channel{Id: otherChannel, TeamId: teamID, Name: "town-square", Type: model.ChannelTypeOpen}
	api.byName["ops/alerts"] = alertsChannel

	for _, u := range []string{channelAdmin, teamAdmin, sysadmin, member, readOnly, outsider, dbAdmin} {
		api.users[u] = &model.User{Id: u, Username: "user" + u[:6]}
		api.teamMembers[teamID] = ensureMap(api.teamMembers[teamID])
		api.teamMembers[teamID][u] = &model.TeamMember{TeamId: teamID, UserId: u, SchemeAdmin: u == teamAdmin}
	}
	addMember := func(channelID, userID string, admin bool) {
		if api.channelMembers[channelID] == nil {
			api.channelMembers[channelID] = map[string]*model.ChannelMember{}
		}
		api.channelMembers[channelID][userID] = &model.ChannelMember{ChannelId: channelID, UserId: userID, SchemeAdmin: admin}
	}
	for _, u := range []string{channelAdmin, teamAdmin, sysadmin, member, readOnly, dbAdmin} {
		addMember(alertsChannel, u, u == channelAdmin)
	}
	addMember(dbChannel, dbAdmin, true)
	addMember(dbChannel, teamAdmin, false)
	addMember(dbChannel, sysadmin, false)
	api.sysadmins[sysadmin] = true
	api.cannotPost[readOnly] = true

	instances := []instanceConfig{{
		Name: "prod",
		URL:  am.server.URL,
		Routes: []routeConfig{
			{Receiver: "antimatter", Team: "ops", Channel: "alerts"},
			{Receiver: "db", ChannelID: dbChannel},
		},
	}}
	secrets := map[string]instanceSecretConfig{"prod": {WebhookSecret: testSecret, BearerToken: testBearerToken}}
	instancesJSON, _ := json.Marshal(instances)
	secretsJSON, _ := json.Marshal(secrets) //nolint:gosec // the test settings hold made-up secrets
	cfg := &configuration{Instances: string(instancesJSON), InstanceSecrets: string(secretsJSON)}
	for _, o := range options {
		o(cfg)
	}
	api.config = cfg

	env.p = &Plugin{}
	env.p.SetAPI(api)
	env.p.now = func() time.Time { return env.now }
	require.NoError(t, env.p.OnConfigurationChange())
	require.NoError(t, env.p.OnActivate())
	return env
}

func ensureMap(m map[string]*model.TeamMember) map[string]*model.TeamMember {
	if m == nil {
		return map[string]*model.TeamMember{}
	}
	return m
}

// serve sends a request to the app as the server would, with the person's ID ("" for none).
func (env *testEnv) serve(method, path, userID string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if userID != "" {
		req.Header.Set("Mattermost-User-Id", userID)
	}
	w := httptest.NewRecorder()
	env.p.ServeHTTP(&plugin.Context{}, w, req)
	return w
}

func webhookPath(instance, secret string) string {
	return "/webhook/" + instance + "/" + secret
}

func firingPayload(groupKey, receiver string, alerts ...webhookAlert) *webhookPayload {
	status := statusResolved
	for _, a := range alerts {
		if a.Status == statusFiring {
			status = statusFiring
		}
	}
	return &webhookPayload{
		Version:      "4",
		GroupKey:     groupKey,
		Status:       status,
		Receiver:     receiver,
		GroupLabels:  map[string]string{"alertname": "HighCPU"},
		CommonLabels: map[string]string{"alertname": "HighCPU", "instance": "www-1", "severity": "critical"},
		ExternalURL:  "http://alertmanager:9093",
		Alerts:       alerts,
	}
}

func highCPU(status string) webhookAlert {
	a := webhookAlert{
		Status:       status,
		Labels:       map[string]string{"alertname": "HighCPU", "instance": "www-1", "severity": "critical"},
		Annotations:  map[string]string{"summary": "CPU above 90% on www-1", "description": "CPU has been above 90% for 5 minutes."},
		StartsAt:     time.Date(2026, 10, 24, 17, 55, 0, 0, time.UTC),
		GeneratorURL: "http://prometheus:9090/graph?g0.expr=cpu",
		Fingerprint:  "abc123",
	}
	if status == statusResolved {
		a.EndsAt = time.Date(2026, 10, 24, 18, 10, 0, 0, time.UTC)
	}
	return a
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

// postAlert sends a webhook with the right secret and expects it taken.
func (env *testEnv) postAlert(payload *webhookPayload) {
	env.t.Helper()
	w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", mustJSON(env.t, payload))
	require.Equal(env.t, http.StatusOK, w.Code, w.Body.String())
}

// rootPosts gives the created posts that aren't replies.
func (env *testEnv) rootPosts() []*model.Post {
	var out []*model.Post
	for _, p := range env.api.createdPosts() {
		if p.RootId == "" {
			out = append(out, p)
		}
	}
	return out
}

func (env *testEnv) replies() []*model.Post {
	var out []*model.Post
	for _, p := range env.api.createdPosts() {
		if p.RootId != "" {
			out = append(out, p)
		}
	}
	return out
}

func attachmentOf(t *testing.T, post *model.Post) *model.MessageAttachment {
	t.Helper()
	attachments := post.Attachments()
	require.Len(t, attachments, 1)
	return attachments[0]
}

func actionIDs(a *model.MessageAttachment) []string {
	var out []string
	for _, action := range a.Actions {
		out = append(out, action.Id)
	}
	return out
}

// click sends a button click of a post as the server would.
func (env *testEnv) click(userID, postID, actionID string) *model.PostActionIntegrationResponse {
	env.t.Helper()
	post := env.api.post(postID)
	require.NotNil(env.t, post)
	var context map[string]any
	for _, a := range attachmentOf(env.t, post).Actions {
		if a.Id == actionID {
			context = a.Integration.Context
		}
	}
	require.NotNil(env.t, context, "no button %s", actionID)
	return env.clickWith(userID, postID, context)
}

func (env *testEnv) clickWith(userID, postID string, context map[string]any) *model.PostActionIntegrationResponse {
	env.t.Helper()
	body := mustJSON(env.t, &model.PostActionIntegrationRequest{UserId: userID, PostId: postID, ChannelId: alertsChannel, TriggerId: "trigger", Context: context})
	w := env.serve(http.MethodPost, "/action", userID, body)
	require.Equal(env.t, http.StatusOK, w.Code)
	var resp model.PostActionIntegrationResponse
	require.NoError(env.t, json.Unmarshal(w.Body.Bytes(), &resp))
	return &resp
}

// tool runs a tool for a person.
func (env *testEnv) tool(userID, name string, args any) *model.AIToolResult {
	env.t.Helper()
	return env.p.ExecuteAITool(&plugin.Context{}, &model.AIToolExecution{CallId: model.NewId(), Tool: name, Arguments: mustJSON(env.t, args), UserId: userID, ChannelId: otherChannel})
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
