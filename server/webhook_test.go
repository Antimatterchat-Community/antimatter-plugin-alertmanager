// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookPostsAlert(t *testing.T) {
	env := newTestEnv(t)
	env.postAlert(firingPayload("{}:{alertname=\"HighCPU\"}", "antimatter", highCPU(statusFiring)))

	posts := env.rootPosts()
	require.Len(t, posts, 1)
	post := posts[0]
	assert.Equal(t, alertsChannel, post.ChannelId)
	assert.Equal(t, botUserID, post.UserId)
	assert.Equal(t, true, post.GetProp(postPropGroup))

	a := attachmentOf(t, post)
	require.NoError(t, a.IsValid(), "the server accepts the card")
	assert.Equal(t, "Firing: HighCPU", a.Title)
	assert.Equal(t, "danger", a.Color)
	assert.Equal(t, "http://prometheus:9090/graph?g0.expr=cpu", a.TitleLink)
	assert.Contains(t, a.Text, "`www-1`")
	assert.Contains(t, a.Text, "CPU above 90% on www-1")
	assert.Contains(t, a.Text, "CPU has been above 90% for 5 minutes.")
	assert.Contains(t, a.Text, "Started 2026-10-24 17:55 UTC")
	assert.Contains(t, a.Text, "[Source](http://prometheus:9090/graph?g0.expr=cpu)")
	assert.Equal(t, []string{actionSilence1h, actionSilence4h, actionSilenceUntil}, actionIDs(a))
	for _, action := range a.Actions {
		assert.Equal(t, "/plugins/"+manifest.Id+"/action", action.Integration.URL)
	}
	var fields []string
	for _, f := range a.Fields {
		fields = append(fields, f.Title+"="+f.Value.(string))
	}
	assert.Equal(t, []string{"Severity=critical", "Instance=www-1"}, fields)
}

func TestWebhookRefusals(t *testing.T) {
	valid := firingPayload("g1", "antimatter", highCPU(statusFiring))

	t.Run("wrong secret and unknown instance get the same 404", func(t *testing.T) {
		env := newTestEnv(t)
		body := mustJSON(t, valid)
		wrong := env.serve(http.MethodPost, webhookPath("prod", "not-the-secret-0123456789abcdef"), "", body)
		unknown := env.serve(http.MethodPost, webhookPath("staging", testSecret), "", body)
		empty := env.serve(http.MethodPost, webhookPath("prod", ""), "", body)
		prefix := env.serve(http.MethodPost, webhookPath("prod", testSecret[:len(testSecret)-1]), "", body)
		first := asResponse(wrong)
		for _, w := range []*testResponse{first, asResponse(unknown), asResponse(empty), asResponse(prefix)} {
			assert.Equal(t, http.StatusNotFound, w.code)
			assert.Equal(t, first.body, w.body)
		}
		assert.Empty(t, env.api.createdPosts())
		assert.NotContains(t, env.api.allLogs(), testSecret)
		assert.NotContains(t, env.api.allLogs(), "not-the-secret")
	})

	t.Run("other methods and paths get 404", func(t *testing.T) {
		env := newTestEnv(t)
		for _, w := range []*testResponse{
			asResponse(env.serve(http.MethodGet, webhookPath("prod", testSecret), "", nil)),
			asResponse(env.serve(http.MethodPost, webhookPath("prod", testSecret)+"/x", "", mustJSON(t, valid))),
			asResponse(env.serve(http.MethodPost, "/webhook/prod", "", mustJSON(t, valid))),
		} {
			assert.Equal(t, http.StatusNotFound, w.code)
		}
		assert.Empty(t, env.api.createdPosts())
	})

	t.Run("oversized body", func(t *testing.T) {
		env := newTestEnv(t)
		big := mustJSON(t, valid)
		big = append(big[:len(big)-1], []byte(`,"padding":"`+strings.Repeat("x", maxWebhookBody)+`"}`)...)
		w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", big)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
		assert.Empty(t, env.api.createdPosts())
	})

	t.Run("malformed JSON", func(t *testing.T) {
		env := newTestEnv(t)
		for _, body := range [][]byte{[]byte(`{"version": "4", "alerts": [`), []byte(`not json`), []byte(``)} {
			w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", body)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		}
		assert.Empty(t, env.api.createdPosts())
	})

	t.Run("other versions", func(t *testing.T) {
		env := newTestEnv(t)
		old := *valid
		old.Version = "3"
		w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", mustJSON(t, &old))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, env.api.createdPosts())
	})

	t.Run("rate limit", func(t *testing.T) {
		env := newTestEnv(t)
		body := mustJSON(t, firingPayload("g1", "unrouted", highCPU(statusFiring)))
		for range webhookBurst {
			w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", body)
			require.Equal(t, http.StatusOK, w.Code)
		}
		w := env.serve(http.MethodPost, webhookPath("prod", testSecret), "", mustJSON(t, valid))
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Empty(t, env.api.createdPosts())

		// Wrong secrets don't use up the instance's budget...
		env2 := newTestEnv(t)
		for range 3 * webhookBurst {
			env2.serve(http.MethodPost, webhookPath("prod", "wrong-secret-0123456789abcdefgh"), "", body)
		}
		env2.postAlert(valid)
		assert.Len(t, env2.rootPosts(), 1)

		// ...and the budget comes back with time.
		env.now = env.now.Add(time.Minute)
		env.postAlert(valid)
		assert.Len(t, env.rootPosts(), 1)
	})
}

type testResponse struct {
	code int
	body string
}

func asResponse(w interface {
	Result() *http.Response
},
) *testResponse {
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return &testResponse{code: resp.StatusCode, body: buf.String()}
}

func TestWebhookGroupingAndResolution(t *testing.T) {
	env := newTestEnv(t)
	group := "{}:{alertname=\"HighCPU\"}"
	env.postAlert(firingPayload(group, "antimatter", highCPU(statusFiring)))
	require.Len(t, env.rootPosts(), 1)
	postID := env.rootPosts()[0].Id

	// A repeat updates the post.
	env.now = env.now.Add(4 * time.Hour)
	second := highCPU(statusFiring)
	second.Labels = map[string]string{"alertname": "HighCPU", "instance": "www-2", "severity": "critical"}
	repeat := firingPayload(group, "antimatter", highCPU(statusFiring), second)
	repeat.CommonLabels = map[string]string{"alertname": "HighCPU", "severity": "critical"}
	env.postAlert(repeat)
	require.Len(t, env.rootPosts(), 1)
	assert.Empty(t, env.replies())
	updated := env.api.post(postID)
	assert.Equal(t, "Firing (2): HighCPU", attachmentOf(t, updated).Title)
	assert.Contains(t, attachmentOf(t, updated).Text, "`www-2`")

	// Resolving updates that same post and replies "Resolved".
	resolved := firingPayload(group, "antimatter", highCPU(statusResolved))
	env.postAlert(resolved)
	require.Len(t, env.rootPosts(), 1)
	a := attachmentOf(t, env.api.post(postID))
	assert.Equal(t, "Resolved: HighCPU", a.Title)
	assert.Equal(t, "good", a.Color)
	assert.Empty(t, a.Actions)
	require.Len(t, env.replies(), 1)
	assert.Equal(t, postID, env.replies()[0].RootId)
	assert.Contains(t, env.replies()[0].Message, "Resolved")

	// A repeat of the resolution doesn't reply again.
	env.postAlert(resolved)
	assert.Len(t, env.replies(), 1)
	assert.Len(t, env.rootPosts(), 1)

	// Firing again after resolving is a new incident: a new post.
	env.postAlert(firingPayload(group, "antimatter", highCPU(statusFiring)))
	require.Len(t, env.rootPosts(), 2)
	assert.NotEqual(t, postID, env.rootPosts()[1].Id)

	// Another group gets its own post.
	env.postAlert(firingPayload("other-group", "antimatter", highCPU(statusFiring)))
	assert.Len(t, env.rootPosts(), 3)
}

func TestWebhookDeletedPostGetsANewOne(t *testing.T) {
	env := newTestEnv(t)
	env.postAlert(firingPayload("g", "antimatter", highCPU(statusFiring)))
	first := env.rootPosts()[0].Id
	env.api.mu.Lock()
	delete(env.api.posts, first)
	env.api.mu.Unlock()
	env.postAlert(firingPayload("g", "antimatter", highCPU(statusFiring)))
	require.Len(t, env.rootPosts(), 2)
	rec, _, err := env.p.store.groupForPost(env.rootPosts()[1].Id)
	require.NoError(t, err)
	require.NotNil(t, rec)
}

func TestWebhookRouting(t *testing.T) {
	env := newTestEnv(t)

	env.postAlert(firingPayload("g", "db", highCPU(statusFiring)))
	require.Len(t, env.rootPosts(), 1)
	assert.Equal(t, dbChannel, env.rootPosts()[0].ChannelId)

	env.postAlert(firingPayload("g", "nobody\nfake log line", highCPU(statusFiring)))
	assert.Len(t, env.rootPosts(), 1)
	logs := env.api.allLogs()
	assert.Contains(t, logs, "receiver without a route")
	assert.Contains(t, logs, "nobodyfake log line")
	assert.NotContains(t, logs, testSecret)
	assert.NotContains(t, logs, "/webhook/")
}

func TestWebhookSeverityNone(t *testing.T) {
	watchdog := webhookAlert{Status: statusFiring, Labels: map[string]string{"alertname": "Watchdog", "severity": "none"}}
	payload := firingPayload("watchdog", "antimatter", watchdog)
	payload.CommonLabels = watchdog.Labels

	env := newTestEnv(t)
	env.postAlert(payload)
	assert.Empty(t, env.api.createdPosts())

	// Alongside others, only the Watchdog is left out.
	mixed := firingPayload("mixed", "antimatter", watchdog, highCPU(statusFiring))
	env.postAlert(mixed)
	require.Len(t, env.rootPosts(), 1)
	assert.NotContains(t, attachmentOf(t, env.rootPosts()[0]).Text, "Watchdog")

	withNone := newTestEnv(t, withSeverityNone())
	withNone.postAlert(payload)
	require.Len(t, withNone.rootPosts(), 1)
	assert.Equal(t, "Firing: Watchdog", attachmentOf(t, withNone.rootPosts()[0]).Title)
}

func TestWebhookNeutralisesMentions(t *testing.T) {
	env := newTestEnv(t)
	alert := highCPU(statusFiring)
	alert.Annotations["summary"] = "Ping @channel and <!here>"
	alert.GeneratorURL = "javascript:alert(1)"
	env.postAlert(firingPayload("g", "antimatter", alert))
	a := attachmentOf(t, env.rootPosts()[0])
	assert.NotContains(t, a.Text, "@channel")
	assert.NotContains(t, a.Text, "<!here>")
	assert.NotContains(t, a.Text, "javascript:")
	assert.Empty(t, a.TitleLink)
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(2, 1)
	now := time.Now()
	assert.True(t, l.allow("a", now))
	assert.True(t, l.allow("a", now))
	assert.False(t, l.allow("a", now))
	assert.True(t, l.allow("b", now), "each instance has its own budget")
	assert.True(t, l.allow("a", now.Add(time.Second)))
	assert.False(t, l.allow("a", now.Add(time.Second)))
}
