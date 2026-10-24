// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIToolDefinitions(t *testing.T) {
	env := newTestEnv(t)
	require.Equal(t, 1, env.api.registerCalls, "OnActivate registers the tools")
	require.Len(t, env.api.tools, 4)
	kinds := map[string]string{}
	for _, d := range env.api.tools {
		require.Nil(t, d.IsValid(), d.Name)
		var schema map[string]any
		require.NoError(t, json.Unmarshal(d.InputSchema, &schema), d.Name)
		assert.Equal(t, "object", schema["type"])
		assert.LessOrEqual(t, len(model.AIToolFullName(manifest.Id, d.Name)), model.AIAgentToolNameMaxLength)
		assert.True(t, model.IsValidAIAgentToolName(model.AIToolFullName(manifest.Id, d.Name)), d.Name)
		kinds[d.Name] = d.Kind
	}
	assert.Equal(t, map[string]string{
		toolListAlerts:    model.AIToolKindRead,
		toolListSilences:  model.AIToolKindRead,
		toolCreateSilence: model.AIToolKindExternalWrite,
		toolExpireSilence: model.AIToolKindExternalWrite,
	}, kinds)
}

func sampleAlerts() []amAlert {
	return []amAlert{
		{
			Labels:       map[string]string{"alertname": "HighCPU", "instance": "www-1", "severity": "critical", "job": "node"},
			Annotations:  map[string]string{"summary": "CPU above 90% on www-1"},
			StartsAt:     time.Date(2026, 10, 24, 17, 55, 0, 0, time.UTC),
			GeneratorURL: "http://prometheus:9090/graph",
			Receivers:    []amReceiver{{Name: "antimatter"}},
			Status:       amAlertStatus{State: "active"},
		},
		{
			Labels:    map[string]string{"alertname": "DiskFull", "instance": "db-1", "severity": "warning"},
			Receivers: []amReceiver{{Name: "db"}},
			Status:    amAlertStatus{State: "active"},
		},
		{
			Labels:    map[string]string{"alertname": "InstanceDown", "instance": "www-2", "severity": "critical"},
			Receivers: []amReceiver{{Name: "antimatter"}},
			Status:    amAlertStatus{State: "suppressed", SilencedBy: []string{"s1"}},
		},
		{
			Labels:    map[string]string{"alertname": "Watchdog", "severity": "none"},
			Receivers: []amReceiver{{Name: "antimatter"}},
			Status:    amAlertStatus{State: "active"},
		},
		{
			Labels:    map[string]string{"alertname": "Unrouted"},
			Receivers: []amReceiver{{Name: "elsewhere"}},
			Status:    amAlertStatus{State: "active"},
		},
	}
}

func decodeResult[T any](t *testing.T, result *model.AIToolResult) *T {
	t.Helper()
	require.Empty(t, result.Error)
	var out T
	require.NoError(t, json.Unmarshal([]byte(result.Text), &out), result.Text)
	return &out
}

func TestListAlertsTool(t *testing.T) {
	env := newTestEnv(t)
	env.am.alerts = sampleAlerts()

	// dbAdmin reads both channels.
	out := decodeResult[toolDisplayResult](t, env.tool(dbAdmin, toolListAlerts, map[string]any{"filter": []string{`severity=~"critical|warning"`}, "active": true}))
	assert.Equal(t, "Alerts of prod: 2 firing (1 critical, 1 warning), 1 silenced.", out.Summary)
	require.Len(t, out.Attachments, 3)
	first := out.Attachments[0]
	assert.Equal(t, "HighCPU", first.Title)
	assert.Equal(t, "CPU above 90% on www-1", first.Text)
	assert.Equal(t, "http://prometheus:9090/graph", first.TitleLink)
	assert.Equal(t, fieldValue(t, first, "Severity"), "critical")
	assert.Equal(t, fieldValue(t, first, "Target"), "www-1")
	assert.Equal(t, fieldValue(t, first, "Since"), "2026-10-24 17:55 UTC")
	assert.Equal(t, "danger", first.Color)
	assert.Equal(t, "good", toolAlertColour(statusResolved, "critical"), "sanity: resolved is always green")
	assert.Equal(t, "#8b8f97", out.Attachments[2].Color, "silenced is the neutral grey, not its severity colour")

	calls := env.am.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, "/api/v2/alerts", calls[0].Path)
	assert.Equal(t, []string{`severity=~"critical|warning"`}, calls[0].Query["filter"])
	assert.Equal(t, []string{"true"}, calls[0].Query["active"])
	assert.Equal(t, "Bearer "+testBearerToken, calls[0].Auth)

	// member reads the alerts channel only: the db receiver's alerts are left out.
	out = decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{}))
	require.Len(t, out.Attachments, 2)

	// Naming a receiver one can't see is the same as naming one that doesn't exist.
	hidden := env.tool(member, toolListAlerts, map[string]any{"receiver": "db"})
	missing := env.tool(member, toolListAlerts, map[string]any{"receiver": "nope"})
	assert.Equal(t, errUnknownReceiver.Error(), hidden.Error)
	assert.Equal(t, hidden.Error, missing.Error)

	out = decodeResult[toolDisplayResult](t, env.tool(dbAdmin, toolListAlerts, map[string]any{"receiver": "db"}))
	require.Len(t, out.Attachments, 1)
	last := env.am.calls()[len(env.am.calls())-1]
	assert.Equal(t, []string{"^(?:db)$"}, last.Query["receiver"])

	// The instance must be one the person can see.
	assert.Equal(t, errUnknownInstance.Error(), env.tool(member, toolListAlerts, map[string]any{"alertmanager": "staging"}).Error)
	env.api.mu.Lock()
	delete(env.api.teamMembers[teamID], outsider)
	env.api.mu.Unlock()
	assert.Equal(t, errUnknownInstance.Error(), env.tool(outsider, toolListAlerts, map[string]any{}).Error)

	// Bad arguments.
	assert.NotEmpty(t, env.tool(member, toolListAlerts, map[string]any{"bogus": 1}).Error)
	assert.NotEmpty(t, env.tool(member, toolListAlerts, map[string]any{"filter": []string{"a\nb"}}).Error)
}

// TestListAlertsToolNoMatches checks the calm, green "no alerts" attachment, scoped to the one
// instance looked at.
func TestListAlertsToolNoMatches(t *testing.T) {
	env := newTestEnv(t)
	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{}))
	require.Len(t, out.Attachments, 1)
	assert.Equal(t, "No alerts for prod.", out.Summary)
	assert.Equal(t, "No alerts for prod.", out.Attachments[0].Text)
	assert.Equal(t, "good", out.Attachments[0].Color)
}

// TestListAlertsToolManyAlertsTrailer checks a result with more than the shown cap gets a
// trailing "+N more" attachment, and an unsafe (non-http(s)) generator URL is dropped rather than
// carried into the attachment's link.
func TestListAlertsToolManyAlertsTrailer(t *testing.T) {
	env := newTestEnv(t)
	var alerts []amAlert
	for i := range maxShownAlertAttachments + 3 {
		alerts = append(alerts, amAlert{
			Labels:       map[string]string{"alertname": fmt.Sprintf("Alert%d", i), "instance": "www-1"},
			Receivers:    []amReceiver{{Name: "antimatter"}},
			Status:       amAlertStatus{State: "active"},
			GeneratorURL: "javascript:alert(1)",
		})
	}
	env.am.alerts = alerts
	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{}))
	require.Len(t, out.Attachments, maxShownAlertAttachments+1)
	last := out.Attachments[maxShownAlertAttachments]
	assert.Contains(t, last.Text, "+3 more")
	for _, a := range out.Attachments[:maxShownAlertAttachments] {
		assert.Empty(t, a.TitleLink, "an unsafe generator URL must never reach the attachment's link")
		// No severity label defaults to "info" (never left blank or "unknown").
		assert.Equal(t, "info", fieldValue(t, a, "Severity"))
	}
}

func fieldValue(t *testing.T, a *model.MessageAttachment, title string) string {
	t.Helper()
	for _, f := range a.Fields {
		if f.Title == title {
			v, _ := f.Value.(string)
			return v
		}
	}
	return ""
}

func TestListSilencesTool(t *testing.T) {
	env := newTestEnv(t)
	equal := true
	env.am.silences = []amSilence{
		{ID: "s-1", Status: amSilenceStatus{State: "active"}, Matchers: []amMatcher{{Name: "alertname", Value: "HighCPU", IsEqual: &equal}}, EndsAt: time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC), CreatedBy: "@maya", Comment: "deploy"},
		{ID: "s-2", Status: amSilenceStatus{State: "expired"}, Matchers: []amMatcher{{Name: "alertname", Value: "Old"}}},
		{ID: "s-3", Status: amSilenceStatus{State: "pending"}, Matchers: []amMatcher{{Name: "instance", Value: "www-.*", IsRegex: true}}, StartsAt: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC), EndsAt: time.Date(2026, 10, 25, 2, 0, 0, 0, time.UTC)},
	}
	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListSilences, map[string]any{"filter": `alertname="HighCPU"`}))
	assert.Equal(t, "Silences of prod: 1 active, 1 pending.", out.Summary)
	require.Len(t, out.Attachments, 1)
	table := out.Attachments[0]
	assert.Equal(t, "Silences of prod", table.Title)
	assert.Contains(t, table.Text, `alertname="HighCPU"`)
	assert.Contains(t, table.Text, "2026-10-24 20:00 UTC")
	assert.Contains(t, table.Text, "@maya")
	assert.Contains(t, table.Text, "deploy")
	assert.Contains(t, table.Text, `instance=~"www-.*"`)
	assert.Contains(t, table.Text, "2026-10-25 00:00 UTC")
	assert.NotContains(t, table.Text, "Old", "the expired silence isn't shown")
	assert.Equal(t, []string{`alertname="HighCPU"`}, env.am.calls()[0].Query["filter"])
}

// TestListSilencesToolNoMatches checks the calm "no active silences" attachment.
func TestListSilencesToolNoMatches(t *testing.T) {
	env := newTestEnv(t)
	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListSilences, map[string]any{}))
	require.Len(t, out.Attachments, 1)
	assert.Equal(t, "Silences of prod: No active silences.", out.Summary)
	assert.Equal(t, "good", out.Attachments[0].Color)
}

func TestCreateSilenceTool(t *testing.T) {
	args := map[string]any{
		"matchers": []map[string]any{{"name": "alertname", "value": "HighCPU"}, {"name": "instance", "value": "www-.*", "is_regex": true}},
		"duration": "2h",
		"comment":  "Deploying",
	}
	t.Run("refused without the right in every routed channel, though the server confirmed it", func(t *testing.T) {
		for _, mode := range []string{silenceByChannelAdmins, silenceByChannelPosters, silenceBySystemAdmins} {
			env := newTestEnv(t, withPermission(mode))
			refused := []string{channelAdmin, member, readOnly, outsider}
			switch mode {
			case silenceBySystemAdmins:
				refused = append(refused, teamAdmin, dbAdmin)
			case silenceByChannelAdmins:
				refused = append(refused, dbAdmin)
			}
			for _, userID := range refused {
				result := env.tool(userID, toolCreateSilence, args)
				assert.NotEmpty(t, result.Error, mode+" "+userID)
				assert.Empty(t, result.Text)
			}
			assert.Empty(t, env.am.writes(), mode)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		for _, userID := range []string{teamAdmin, sysadmin} {
			env := newTestEnv(t)
			out := decodeResult[silenceResult](t, env.tool(userID, toolCreateSilence, args))
			assert.Equal(t, "Silence created", out.Title)
			assert.Equal(t, "prod", out.Instance)
			assert.Equal(t, "00000000-0000-0000-0000-000000000001", out.ID)
			assert.Equal(t, `alertname="HighCPU", instance=~"www-.*"`, out.Matchers)
			assert.Equal(t, "2026-10-24 20:00 UTC", out.EndsAt)

			writes := env.am.writes()
			require.Len(t, writes, 1)
			assert.Equal(t, http.MethodPost, writes[0].Method)
			assert.Equal(t, "/api/v2/silences", writes[0].Path)
			var sent amPostableSilence
			require.NoError(t, json.Unmarshal([]byte(writes[0].Body), &sent))
			assert.Empty(t, sent.ID)
			assert.Equal(t, env.now, sent.StartsAt)
			assert.Equal(t, env.now.Add(2*time.Hour), sent.EndsAt)
			assert.Equal(t, "@user"+userID[:6], sent.CreatedBy)
			assert.Equal(t, "Deploying", sent.Comment)
			require.Len(t, sent.Matchers, 2)
			assert.True(t, sent.Matchers[1].IsRegex)
		}
	})

	t.Run("checked arguments", func(t *testing.T) {
		env := newTestEnv(t)
		for name, bad := range map[string]map[string]any{
			"no matchers":   {"matchers": []any{}, "duration": "1h", "comment": "x"},
			"bad name":      {"matchers": []map[string]any{{"name": "bad name", "value": "x"}}, "duration": "1h", "comment": "x"},
			"bad regex":     {"matchers": []map[string]any{{"name": "a", "value": "(", "is_regex": true}}, "duration": "1h", "comment": "x"},
			"matches all":   {"matchers": []map[string]any{{"name": "a", "value": ".*", "is_regex": true}}, "duration": "1h", "comment": "x"},
			"too long":      {"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "45d", "comment": "x"},
			"too short":     {"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "10s", "comment": "x"},
			"bad duration":  {"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "soon", "comment": "x"},
			"no comment":    {"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "1h", "comment": " "},
			"unknown field": {"matchers": []map[string]any{{"name": "a", "value": "b"}}, "duration": "1h", "comment": "x", "created_by": "admin"},
		} {
			assert.NotEmpty(t, env.tool(teamAdmin, toolCreateSilence, bad).Error, name)
		}
		assert.Empty(t, env.am.writes())
	})
}

func TestExpireSilenceTool(t *testing.T) {
	t.Run("a silence made with a tool needs the instance-wide right", func(t *testing.T) {
		env := newTestEnv(t)
		created := decodeResult[silenceResult](t, env.tool(teamAdmin, toolCreateSilence, map[string]any{
			"matchers": []map[string]any{{"name": "alertname", "value": "HighCPU"}}, "duration": "1h", "comment": "x",
		}))
		for _, userID := range []string{channelAdmin, member, dbAdmin, outsider} {
			assert.NotEmpty(t, env.tool(userID, toolExpireSilence, map[string]any{"id": created.ID}).Error, userID)
		}
		require.Len(t, env.am.writes(), 1, "no DELETE")

		out := decodeResult[silenceResult](t, env.tool(sysadmin, toolExpireSilence, map[string]any{"id": created.ID}))
		assert.Equal(t, "Silence expired", out.Title)
		writes := env.am.writes()
		require.Len(t, writes, 2)
		assert.Equal(t, http.MethodDelete, writes[1].Method)
		assert.Equal(t, "/api/v2/silence/"+created.ID, writes[1].Path)

		again := decodeResult[silenceResult](t, env.tool(sysadmin, toolExpireSilence, map[string]any{"id": created.ID}))
		assert.Equal(t, "Silence already expired", again.Title)
		assert.Len(t, env.am.writes(), 2)
	})

	t.Run("a silence set from a post needs the right in its channel", func(t *testing.T) {
		env := newTestEnv(t)
		postID := env.alertPost()
		env.click(channelAdmin, postID, actionSilence1h)
		id := "00000000-0000-0000-0000-000000000001"

		assert.NotEmpty(t, env.tool(member, toolExpireSilence, map[string]any{"id": id}).Error)
		require.Len(t, env.am.writes(), 1)

		// channelAdmin hasn't the instance-wide right but has it in the post's channel.
		out := decodeResult[silenceResult](t, env.tool(channelAdmin, toolExpireSilence, map[string]any{"id": id}))
		assert.Equal(t, "Silence expired", out.Title)
		require.Len(t, env.am.writes(), 2)
		// The post shows it.
		assert.Equal(t, []string{actionSilence1h, actionSilence4h, actionSilenceUntil}, actionIDs(attachmentOf(t, env.api.post(postID))))
	})

	t.Run("unknown and malformed IDs", func(t *testing.T) {
		env := newTestEnv(t)
		assert.Equal(t, errNoSuchSilence.Error(), env.tool(sysadmin, toolExpireSilence, map[string]any{"id": "../alerts"}).Error)
		assert.Equal(t, errNoSuchSilence.Error(), env.tool(sysadmin, toolExpireSilence, map[string]any{"id": "missing"}).Error)
		assert.Empty(t, env.am.writes())
	})
}

func TestToolNeedsAPerson(t *testing.T) {
	env := newTestEnv(t)
	result := env.p.ExecuteAITool(nil, &model.AIToolExecution{Tool: toolListAlerts})
	assert.NotEmpty(t, result.Error)
	assert.NotEmpty(t, env.tool(member, "drop_tables", map[string]any{}).Error)
}

func TestParseSilenceDuration(t *testing.T) {
	for text, want := range map[string]time.Duration{"30m": 30 * time.Minute, "2h": 2 * time.Hour, "1h30m": 90 * time.Minute, "1d": 24 * time.Hour, "1w": 7 * 24 * time.Hour, "1.5d": 36 * time.Hour} {
		got, err := parseSilenceDuration(text)
		require.NoError(t, err, text)
		assert.Equal(t, want, got, text)
	}
	for _, text := range []string{"", "soon", "-1d", "d"} {
		_, err := parseSilenceDuration(text)
		assert.Error(t, err, text)
	}
}

// addInstance adds an Alertmanager instance routed, like prod, to ops/alerts by community and channel name.
func (env *testEnv) addInstance(name string) *fakeAM {
	env.t.Helper()
	am := newFakeAM(env.t)
	var instances []instanceConfig
	require.NoError(env.t, json.Unmarshal([]byte(env.api.config.Instances), &instances))
	instances = append(instances, instanceConfig{Name: name, URL: am.server.URL, Routes: []routeConfig{{Receiver: "antimatter", Team: "ops", Channel: "alerts"}}})
	secrets := map[string]instanceSecretConfig{}
	require.NoError(env.t, json.Unmarshal([]byte(env.api.config.InstanceSecrets), &secrets))
	secrets[name] = instanceSecretConfig{WebhookSecret: testSecret}
	env.api.config.Instances = string(mustJSON(env.t, instances))
	env.api.config.InstanceSecrets = string(mustJSON(env.t, secrets))
	require.NoError(env.t, env.p.OnConfigurationChange())
	return am
}

// A route given by community and channel name is visible to the members of that channel, with the instance named
// or not, and resolves to the channel the webhook posts in. Seen on amdev: a system admin member of the routed
// channel was told there was no instance she could see.
func TestRouteByNamesIsVisibleToMembers(t *testing.T) {
	env := newTestEnv(t)
	env.am.alerts = sampleAlerts()
	env.postAlert(firingPayload("g1", "antimatter", highCPU(statusFiring)))
	require.Len(t, env.rootPosts(), 1)
	require.Equal(t, alertsChannel, env.rootPosts()[0].ChannelId, "the webhook posts in ops/alerts")

	for _, userID := range []string{sysadmin, member, channelAdmin} {
		for _, args := range []map[string]any{{}, {"alertmanager": "prod"}} {
			alerts := decodeResult[toolDisplayResult](t, env.tool(userID, toolListAlerts, args))
			assert.Contains(t, alerts.Summary, "Alerts of prod")
			assert.NotEmpty(t, alerts.Attachments)
			silences := decodeResult[toolDisplayResult](t, env.tool(userID, toolListSilences, args))
			assert.Equal(t, "Silences of prod", silences.Attachments[0].Title)
		}
	}

	// Someone outside the channel and its community sees nothing, named or not.
	env.api.mu.Lock()
	delete(env.api.teamMembers[teamID], outsider)
	env.api.mu.Unlock()
	for _, args := range []map[string]any{{}, {"alertmanager": "prod"}} {
		assert.Equal(t, errUnknownInstance.Error(), env.tool(outsider, toolListAlerts, args).Error)
		assert.Equal(t, errUnknownInstance.Error(), env.tool(outsider, toolListSilences, args).Error)
	}
}

// The channel of a route is looked up on every call: a lookup that failed once (the channel not made yet, a typo
// fixed since) isn't remembered.
func TestFailedRouteLookupIsNotKept(t *testing.T) {
	env := newTestEnv(t)
	env.api.mu.Lock()
	delete(env.api.byName, "ops/alerts")
	env.api.mu.Unlock()
	assert.Equal(t, errUnknownInstance.Error(), env.tool(member, toolListAlerts, map[string]any{}).Error)

	env.api.mu.Lock()
	env.api.byName["ops/alerts"] = alertsChannel
	env.api.mu.Unlock()
	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{}))
	assert.Equal(t, "No alerts for prod.", out.Summary)
}

// The assistant fills the properties named like a host with the host a message names: "is www-1 down?" gives a
// target, never the name of an Alertmanager instance.
func TestHostIsATargetNotAnInstance(t *testing.T) {
	env := newTestEnv(t)
	env.am.alerts = sampleAlerts()
	env.am.alerts[0].Labels["instance"] = "www-1:9100"

	for _, d := range env.api.tools {
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		require.NoError(t, json.Unmarshal(d.InputSchema, &schema), d.Name)
		assert.Contains(t, schema.Properties, "alertmanager", d.Name)
		for _, hostLike := range []string{"instance", "host", "hostname", "node", "server", "machine"} {
			assert.NotContains(t, schema.Properties, hostLike, d.Name)
		}
	}

	out := decodeResult[toolDisplayResult](t, env.tool(sysadmin, toolListAlerts, map[string]any{"target": "WWW-1"}))
	require.Len(t, out.Attachments, 1)
	assert.Equal(t, "HighCPU", out.Attachments[0].Title)
	assert.Equal(t, "Alerts of prod: 1 firing (1 critical).", out.Summary)

	out = decodeResult[toolDisplayResult](t, env.tool(sysadmin, toolListAlerts, map[string]any{"target": "www-9"}))
	assert.Equal(t, "No alerts for prod.", out.Summary)

	// An alert without an instance label is about its job.
	assert.True(t, aboutTarget(map[string]string{"job": "node"}, "node"))
	assert.False(t, aboutTarget(map[string]string{"instance": "www-10"}, "www-1"))

	// The old argument is refused rather than taken for an instance name.
	assert.Contains(t, env.tool(sysadmin, toolListAlerts, map[string]any{"instance": "www-1"}).Error, "arguments aren't valid")
	assert.Equal(t, errBadTarget.Error(), env.tool(sysadmin, toolListAlerts, map[string]any{"target": "a\nb"}).Error)
}

// With several instances, the read tools look at every one the person can see when none is named, and the action
// tools need the name.
func TestSeveralInstances(t *testing.T) {
	env := newTestEnv(t)
	env.am.alerts = sampleAlerts()
	staging := env.addInstance("staging")
	staging.alerts = []amAlert{{
		Labels: map[string]string{"alertname": "HighLatency", "instance": "www-3", "severity": "warning"}, Receivers: []amReceiver{{Name: "antimatter"}},
		Status: amAlertStatus{State: "active"},
	}}

	out := decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{}))
	assert.Contains(t, out.Summary, "Alerts:")
	byInstance := map[string]int{}
	for _, a := range out.Attachments {
		byInstance[fieldValue(t, a, "Instance")]++
	}
	assert.Equal(t, map[string]int{"prod": 2, "staging": 1}, byInstance)
	require.Len(t, env.am.calls(), 1)
	require.Len(t, staging.calls(), 1)

	silences := decodeResult[toolDisplayResult](t, env.tool(member, toolListSilences, map[string]any{}))
	assert.Equal(t, "Silences", silences.Attachments[0].Title)
	require.Len(t, env.am.calls(), 2)
	require.Len(t, staging.calls(), 2)

	only := decodeResult[toolDisplayResult](t, env.tool(member, toolListAlerts, map[string]any{"alertmanager": "staging"}))
	assert.Contains(t, only.Summary, "Alerts of staging")
	require.Len(t, only.Attachments, 1)
	assert.Len(t, env.am.calls(), 2, "prod isn't asked")

	create := map[string]any{"matchers": []map[string]any{{"name": "alertname", "value": "HighCPU"}}, "duration": "1h", "comment": "x"}
	result := env.tool(sysadmin, toolCreateSilence, create)
	assert.Equal(t, errNameInstance.Error()+": prod, staging", result.Error)
	assert.Contains(t, env.tool(sysadmin, toolExpireSilence, map[string]any{"id": "x"}).Error, errNameInstance.Error())
	assert.Empty(t, env.am.writes())
	assert.Empty(t, staging.writes())

	create["alertmanager"] = "staging"
	created := decodeResult[silenceResult](t, env.tool(sysadmin, toolCreateSilence, create))
	assert.Equal(t, "staging", created.Instance)
	assert.Len(t, staging.writes(), 1)
	assert.Empty(t, env.am.writes())
}
