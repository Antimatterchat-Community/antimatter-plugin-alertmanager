// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func settingsOf(t *testing.T, instances, secrets string) (*settings, string) {
	t.Helper()
	s, problems := parseSettings(&configuration{Instances: instances, InstanceSecrets: secrets})
	return s, strings.Join(problems, "\n")
}

func TestParseSettings(t *testing.T) {
	routes := `"routes": [{"receiver": "a", "team": "ops", "channel": "alerts"}, {"receiver": "b", "channel_id": "` + model.NewId() + `"}]`
	good := `[{"name": "prod", "url": "http://alertmanager:9093/", ` + routes + `}]`
	secret := `{"prod": {"webhook_secret": "` + testSecret + `", "username": "u", "password": "` + testPassword + `"}}`

	s, problems := settingsOf(t, good, secret)
	require.Empty(t, problems)
	require.Equal(t, []string{"prod"}, s.names)
	inst := s.instances["prod"]
	assert.Equal(t, "http://alertmanager:9093", inst.baseURL.String())
	assert.Equal(t, "Basic "+basicAuthValue("u", testPassword), inst.authHeader)
	assert.Len(t, inst.routes, 2)
	assert.True(t, inst.checkWebhookSecret(testSecret))
	assert.False(t, inst.checkWebhookSecret(testSecret+"x"))
	assert.False(t, inst.checkWebhookSecret(""))
	var none *instance
	assert.False(t, none.checkWebhookSecret(testSecret))
	assert.Equal(t, silenceByChannelAdmins, s.silencePermission)

	for name, tc := range map[string]struct{ instances, secrets, problem string }{
		"no secret":         {good, `{}`, "no webhook secret"},
		"short secret":      {good, `{"prod": {"webhook_secret": "short"}}`, "24 to 256 characters"},
		"secret with slash": {good, `{"prod": {"webhook_secret": "abc/defghijklmnopqrstuvwxyz0123"}}`, "may only hold"},
		"both auths":        {good, `{"prod": {"webhook_secret": "` + testSecret + `", "bearer_token": "t", "password": "p"}}`, "not both"},
		"user in url":       {`[{"name": "prod", "url": "http://u:` + testPassword + `@am:9093", ` + routes + `}]`, secret, "must not hold a user name"},
		"bad scheme":        {`[{"name": "prod", "url": "file:///etc/passwd", ` + routes + `}]`, secret, "http or https"},
		"bad name":          {`[{"name": "a/b", "url": "http://am", ` + routes + `}]`, secret, "the name must be"},
		"twice":             {`[{"name": "prod", "url": "http://am", ` + routes + `}, {"name": "prod", "url": "http://am", ` + routes + `}]`, secret, "used twice"},
		"route twice":       {`[{"name": "prod", "url": "http://am", "routes": [{"receiver": "a", "team": "t", "channel": "c", "channel_id": "x"}]}]`, secret, "names its channel twice"},
		"route no channel":  {`[{"name": "prod", "url": "http://am", "routes": [{"receiver": "a", "team": "t"}]}]`, secret, "needs a channel_id"},
		"route no receiver": {`[{"name": "prod", "url": "http://am", "routes": [{"channel_id": "x"}]}]`, secret, "has no receiver"},
		"secret misplaced":  {`[{"name": "prod", "url": "http://am", "webhook_secret": "x", ` + routes + `}]`, secret, "unknown field"},
		"bad json":          {`[{`, secret, "isn't a valid JSON list"},
	} {
		parsed, found := settingsOf(t, tc.instances, tc.secrets)
		assert.Contains(t, found, tc.problem, name)
		if name == "twice" {
			assert.Len(t, parsed.instances, 1, "the first one is kept")
		} else {
			assert.Empty(t, parsed.instances, name)
		}
		assert.NotContains(t, found, testSecret, name)
		assert.NotContains(t, found, testPassword, name)
	}

	// The error of the secrets setting never quotes it.
	_, problems = settingsOf(t, good, `{"prod": {"webhook_secret": "`+testSecret+`"`)
	assert.Contains(t, problems, "isn't a valid JSON object")
	assert.NotContains(t, problems, testSecret)
	_, problems = settingsOf(t, good, `{"prod": "`+testSecret+`"}`)
	assert.NotContains(t, problems, testSecret)

	// One faulty instance doesn't stop the others.
	two := `[{"name": "prod", "url": "http://am", ` + routes + `}, {"name": "lab", "url": "http://lab", ` + routes + `}]`
	s, problems = settingsOf(t, two, secret)
	assert.Equal(t, []string{"prod"}, s.names)
	assert.Contains(t, problems, `instance "lab": it has no webhook secret`)
}

func TestParseSilencePermission(t *testing.T) {
	assert.Equal(t, silenceByChannelAdmins, parseSilencePermission(""))
	assert.Equal(t, silenceByChannelPosters, parseSilencePermission(silenceByChannelPosters))
	assert.Equal(t, silenceBySystemAdmins, parseSilencePermission(silenceBySystemAdmins))
	assert.Equal(t, silenceBySystemAdmins, parseSilencePermission("everyone"), "an unknown value is the strictest")
}

func TestRedact(t *testing.T) {
	s, _ := parseSettings(&configuration{InstanceSecrets: `{"prod": {"webhook_secret": "` + testSecret + `", "username": "u", "password": "` + testPassword + `"}}`})
	text := s.redact("a " + testSecret + " b " + testPassword + " c " + basicAuthValue("u", testPassword))
	assert.Equal(t, "a [redacted] b [redacted] c [redacted]", text)
}

func TestForbiddenAddresses(t *testing.T) {
	for _, address := range []string{
		"169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "168.63.129.16",
		"0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
	} {
		assert.True(t, isForbiddenIP(netip.MustParseAddr(address)), address)
	}
	for _, address := range []string{"127.0.0.1", "::1", "10.0.0.5", "172.18.0.4", "192.168.1.10", "fd12:3456::1", "100.64.0.1", "203.0.113.7", "64:ff9b::a00:5"} {
		assert.False(t, isForbiddenIP(netip.MustParseAddr(address)), address)
	}
}

func TestDialerRefusesMetadata(t *testing.T) {
	dialer := newDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, address := range []string{"169.254.169.254:80", "100.100.100.200:80", "0.0.0.0:80"} {
		_, err := dialer.DialContext(ctx, "tcp", address)
		require.Error(t, err, address)
		assert.ErrorIs(t, err, errForbiddenAddress, address)
	}

	// Loopback, where Alertmanager may run next to the server, is allowed.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	_ = conn.Close()

	// The instance's client goes through it, and follows no redirect.
	inst := &instance{name: "x", baseURL: mustURL(t, "http://169.254.169.254"), client: newAlertmanagerHTTPClient()}
	_, err = inst.alerts(ctx, alertQuery{})
	assert.ErrorIs(t, err, errForbiddenAddress)

	redirect := httptest.NewServer(http.RedirectHandler("http://169.254.169.254/latest/meta-data/", http.StatusFound))
	defer redirect.Close()
	inst = &instance{name: "x", baseURL: mustURL(t, redirect.URL), client: newAlertmanagerHTTPClient()}
	_, err = inst.alerts(ctx, alertQuery{})
	var amErr *amError
	require.ErrorAs(t, err, &amErr)
	assert.Equal(t, http.StatusFound, amErr.Status)
}

func TestConfigurationProblemsAreLoggedWithoutSecrets(t *testing.T) {
	api := newFakeAPI()
	api.config = &configuration{
		Instances:       `[{"name": "prod", "url": "http://am", "routes": []}, {"name": "lab", "url": "ftp://x", "routes": []}]`,
		InstanceSecrets: `{"prod": {"webhook_secret": "` + testSecret + `"}, "lab": {"webhook_secret": "` + testSecret + `", "bearer_token": "` + testBearerToken + `"}}`,
	}
	p := &Plugin{}
	p.SetAPI(api)
	require.NoError(t, p.OnConfigurationChange())
	logs := api.allLogs()
	assert.Contains(t, logs, `instance "lab"`)
	assert.NotContains(t, logs, testSecret)
	assert.NotContains(t, logs, testBearerToken)
	assert.Equal(t, []string{"prod"}, p.getSettings().names)
}

func TestSecretsNeverLeave(t *testing.T) {
	env := newTestEnv(t)
	env.am.alerts = sampleAlerts()
	// Alertmanager echoing a secret back is redacted too.
	env.am.alerts[0].Annotations["summary"] = "token " + testBearerToken
	var outputs []string

	record := func(w *httptest.ResponseRecorder) { outputs = append(outputs, w.Body.String()) }
	record(env.serve(http.MethodPost, webhookPath("prod", testSecret), "", mustJSON(t, firingPayload("g", "antimatter", highCPU(statusFiring)))))
	record(env.serve(http.MethodPost, webhookPath("prod", "wrong-0123456789abcdefghijklmn"), "", nil))
	record(env.serve(http.MethodPost, webhookPath("prod", testSecret), "", []byte("{bad")))
	record(env.serve(http.MethodPost, webhookPath("prod", testSecret), "", mustJSON(t, firingPayload("g", "nowhere", highCPU(statusFiring)))))
	postID := env.rootPosts()[0].Id
	for _, userID := range []string{member, channelAdmin} {
		resp := env.click(userID, postID, actionSilence1h)
		outputs = append(outputs, resp.EphemeralText)
	}
	env.am.failCreate = true
	outputs = append(outputs, env.click(teamAdmin, postID, actionExpire).EphemeralText)
	outputs = append(outputs, env.click(teamAdmin, postID, actionSilence1h).EphemeralText)
	for _, tool := range []string{toolListAlerts, toolListSilences} {
		r := env.tool(dbAdmin, tool, map[string]any{})
		outputs = append(outputs, r.Text, r.Error)
	}
	r := env.tool(sysadmin, toolCreateSilence, map[string]any{"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "1h", "comment": "x"})
	outputs = append(outputs, r.Text, r.Error)
	for _, post := range env.api.createdPosts() {
		outputs = append(outputs, post.Message, mustString(t, post.GetProps()))
	}
	for _, post := range env.api.updatedPosts() {
		outputs = append(outputs, mustString(t, post.GetProps()))
	}
	outputs = append(outputs, env.api.allLogs())

	// The settings the server sends to clients: secret settings are replaced on the server's side.
	var secretSetting bool
	for _, setting := range manifest.SettingsSchema.Settings {
		if setting.Key == "InstanceSecrets" {
			secretSetting = setting.Secret
		}
	}
	assert.True(t, secretSetting, "InstanceSecrets is a secret setting")

	all := strings.Join(outputs, "\n")
	for _, secret := range []string{testSecret, testBearerToken} {
		assert.NotContains(t, all, secret)
	}
	assert.NotContains(t, all, "/webhook/")
}

func mustString(t *testing.T, v any) string {
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return string(data)
}

func TestServeHTTPUnknownPaths(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{"/", "/api/v1/settings", "/action/x", "/webhook"} {
		w := httptest.NewRecorder()
		env.p.ServeHTTP(&plugin.Context{}, w, httptest.NewRequest(http.MethodPost, path, nil))
		assert.Equal(t, http.StatusNotFound, w.Code, path)
	}
	w := httptest.NewRecorder()
	env.p.ServeHTTP(&plugin.Context{}, w, httptest.NewRequest(http.MethodGet, "/action", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
