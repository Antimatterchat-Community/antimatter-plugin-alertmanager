// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alertPost posts a firing HighCPU alert and gives its post's ID.
func (env *testEnv) alertPost() string {
	env.t.Helper()
	env.postAlert(firingPayload("{}:{alertname=\"HighCPU\"}", "antimatter", highCPU(statusFiring)))
	posts := env.rootPosts()
	require.NotEmpty(env.t, posts)
	return posts[len(posts)-1].Id
}

func TestSilenceButtonRights(t *testing.T) {
	cases := map[string]map[string]bool{
		silenceByChannelAdmins:  {channelAdmin: true, teamAdmin: true, sysadmin: true, member: false, readOnly: false, outsider: false},
		silenceByChannelPosters: {channelAdmin: true, teamAdmin: true, sysadmin: true, member: true, readOnly: false, outsider: false},
		silenceBySystemAdmins:   {channelAdmin: false, teamAdmin: false, sysadmin: true, member: false, readOnly: false, outsider: false},
	}
	for mode, users := range cases {
		for userID, allowed := range users {
			t.Run(mode+"/"+userID[:6], func(t *testing.T) {
				env := newTestEnv(t, withPermission(mode))
				postID := env.alertPost()
				resp := env.click(userID, postID, actionSilence1h)
				if allowed {
					assert.Empty(t, resp.EphemeralText)
					require.Len(t, env.am.writes(), 1)
					return
				}
				assert.NotEmpty(t, resp.EphemeralText)
				assert.Empty(t, env.am.writes(), "a refused click doesn't reach Alertmanager")
				assert.Empty(t, env.replies())
			})
		}
	}
}

func TestSilenceButtonOutsiderOfPrivateChannel(t *testing.T) {
	env := newTestEnv(t, withPermission(silenceByChannelPosters))
	env.postAlert(firingPayload("g", "db", highCPU(statusFiring)))
	postID := env.rootPosts()[0].Id
	// channelAdmin isn't in the db channel.
	resp := env.click(channelAdmin, postID, actionSilence4h)
	assert.Equal(t, "You're not a member of the channel the alert is posted in.", resp.EphemeralText)
	assert.Empty(t, env.am.writes())
}

func TestSilenceButtonCreatesSilence(t *testing.T) {
	env := newTestEnv(t)
	postID := env.alertPost()
	resp := env.click(channelAdmin, postID, actionSilence4h)
	require.Empty(t, resp.EphemeralText)

	writes := env.am.writes()
	require.Len(t, writes, 1)
	assert.Equal(t, http.MethodPost, writes[0].Method)
	assert.Equal(t, "/api/v2/silences", writes[0].Path)
	assert.Equal(t, "Bearer "+testBearerToken, writes[0].Auth)
	var sent amPostableSilence
	require.NoError(t, json.Unmarshal([]byte(writes[0].Body), &sent))
	assert.Equal(t, "alertname=\"HighCPU\", instance=\"www-1\"", matchersText(sent.Matchers))
	for _, m := range sent.Matchers {
		assert.False(t, m.IsRegex)
		require.NotNil(t, m.IsEqual)
		assert.True(t, *m.IsEqual)
	}
	assert.Equal(t, env.now, sent.StartsAt)
	assert.Equal(t, env.now.Add(4*time.Hour), sent.EndsAt)
	assert.Equal(t, "@user"+channelAdmin[:6], sent.CreatedBy)
	assert.NotEmpty(t, sent.Comment)

	// The post says who silenced it and until when, and offers the expiry only.
	a := attachmentOf(t, env.api.post(postID))
	require.NoError(t, a.IsValid())
	assert.Equal(t, []string{actionExpire}, actionIDs(a))
	var silenced string
	for _, f := range a.Fields {
		if f.Title == "Silenced" {
			silenced = f.Value.(string)
		}
	}
	assert.Equal(t, "By @user"+channelAdmin[:6]+" until 2026-10-24 22:00 UTC", silenced)
	require.Len(t, env.replies(), 1)
	assert.Contains(t, env.replies()[0].Message, "Silenced by @user"+channelAdmin[:6])

	// Expiring it calls DELETE with its ID and brings the silence buttons back.
	resp = env.click(teamAdmin, postID, actionExpire)
	require.Empty(t, resp.EphemeralText)
	writes = env.am.writes()
	require.Len(t, writes, 2)
	assert.Equal(t, http.MethodDelete, writes[1].Method)
	assert.Equal(t, "/api/v2/silence/00000000-0000-0000-0000-000000000001", writes[1].Path)
	a = attachmentOf(t, env.api.post(postID))
	assert.Equal(t, []string{actionSilence1h, actionSilence4h, actionSilenceUntil}, actionIDs(a))
	assert.Len(t, env.replies(), 2)

	// A silence that has ended isn't shown any more.
	env.click(channelAdmin, postID, actionSilence1h)
	env.now = env.now.Add(2 * time.Hour)
	env.postAlert(firingPayload("{}:{alertname=\"HighCPU\"}", "antimatter", highCPU(statusFiring)))
	assert.Equal(t, []string{actionSilence1h, actionSilence4h, actionSilenceUntil}, actionIDs(attachmentOf(t, env.api.post(postID))))
}

func TestSilenceExpiryRefused(t *testing.T) {
	env := newTestEnv(t)
	postID := env.alertPost()
	env.click(channelAdmin, postID, actionSilence1h)
	resp := env.click(member, postID, actionExpire)
	assert.Equal(t, "You may not silence alerts in this channel.", resp.EphemeralText)
	assert.Len(t, env.am.writes(), 1, "no DELETE")
}

func TestGroupMatchers(t *testing.T) {
	rec := &groupRecord{
		GroupLabels:  map[string]string{"cluster": "eu-1", "job": "node"},
		CommonLabels: map[string]string{"alertname": "InstanceDown", "cluster": "eu-1", "job": "node", "team": "web"},
	}
	assert.Equal(t, `alertname="InstanceDown", cluster="eu-1", job="node"`, matchersText(groupMatchers(rec)))
	assert.Empty(t, groupMatchers(&groupRecord{}))
}

func TestActionChecksThePost(t *testing.T) {
	env := newTestEnv(t)
	postID := env.alertPost()

	// Without the server's user header.
	w := env.serve(http.MethodPost, "/action", "", mustJSON(t, &model.PostActionIntegrationRequest{UserId: channelAdmin, PostId: postID, Context: map[string]any{"action": "silence", "duration": "1h"}}))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// A post that isn't one of the app's alert posts.
	other, _ := env.api.CreatePost(&model.Post{UserId: member, ChannelId: alertsChannel, Message: "hello"})
	resp := env.clickWith(channelAdmin, other.Id, map[string]any{"action": "silence", "duration": "1h"})
	assert.Equal(t, "This isn't an alert post of the Alertmanager app.", resp.EphemeralText)

	// A forged duration or action.
	resp = env.clickWith(channelAdmin, postID, map[string]any{"action": "silence", "duration": "9999h"})
	assert.Equal(t, "Unknown silence.", resp.EphemeralText)
	resp = env.clickWith(channelAdmin, postID, map[string]any{"action": "delete_everything"})
	assert.Equal(t, "Unknown action.", resp.EphemeralText)

	// Expiring without a silence.
	resp = env.clickWith(channelAdmin, postID, map[string]any{"action": "expire"})
	assert.Equal(t, "This alert isn't silenced from here.", resp.EphemeralText)
	assert.Empty(t, env.am.writes())

	// Alertmanager refusing.
	env.am.failCreate = true
	resp = env.click(channelAdmin, postID, actionSilence1h)
	assert.Contains(t, resp.EphemeralText, "refused or didn't answer")
}

func TestSilenceUntilDialog(t *testing.T) {
	env := newTestEnv(t)
	postID := env.alertPost()

	resp := env.click(member, postID, actionSilenceUntil)
	assert.NotEmpty(t, resp.EphemeralText, "no dialog for someone without the right")
	assert.Empty(t, env.api.dialogs)

	resp = env.click(channelAdmin, postID, actionSilenceUntil)
	require.Empty(t, resp.EphemeralText)
	require.Len(t, env.api.dialogs, 1)
	dialog := env.api.dialogs[0]
	assert.Equal(t, "trigger", dialog.TriggerId)
	assert.Equal(t, "/plugins/"+manifest.Id+"/dialog", dialog.URL)
	assert.Equal(t, postID, dialog.Dialog.State)
	require.NoError(t, dialog.Dialog.IsValid())

	submit := func(userID, state string, submission map[string]any) *model.SubmitDialogResponse {
		t.Helper()
		body := mustJSON(t, &model.SubmitDialogRequest{CallbackId: dialogCallbackSilenceUntil, State: state, UserId: userID, ChannelId: alertsChannel, Submission: submission})
		w := env.serve(http.MethodPost, "/dialog", userID, body)
		require.Equal(t, http.StatusOK, w.Code)
		var out model.SubmitDialogResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		return &out
	}

	// The state is checked like a click: someone without the right is refused even with a valid post.
	out := submit(member, postID, map[string]any{"until": "2026-10-25T09:00:00Z"})
	assert.NotEmpty(t, out.Error)
	assert.Empty(t, env.am.writes())

	out = submit(channelAdmin, postID, map[string]any{"until": "yesterday"})
	assert.Contains(t, out.Errors, "until")
	out = submit(channelAdmin, postID, map[string]any{"until": "2026-12-31T09:00:00Z"})
	assert.Equal(t, "A silence can last 30 days at most.", out.Errors["until"])
	out = submit(channelAdmin, postID, map[string]any{"until": "2026-10-24T17:00:00Z"})
	assert.Contains(t, out.Errors["until"], "at least")
	assert.Empty(t, env.am.writes())

	out = submit(channelAdmin, postID, map[string]any{"until": "2026-10-25T09:00:00Z", "comment": "Maintenance @all"})
	assert.Empty(t, out.Error)
	assert.Empty(t, out.Errors)
	writes := env.am.writes()
	require.Len(t, writes, 1)
	var sent amPostableSilence
	require.NoError(t, json.Unmarshal([]byte(writes[0].Body), &sent))
	assert.Equal(t, time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), sent.EndsAt)
	assert.Equal(t, "Maintenance @all", sent.Comment)
	a := attachmentOf(t, env.api.post(postID))
	for _, f := range a.Fields {
		if f.Title == "Silenced" {
			assert.Contains(t, f.Value, "until 2026-10-25 09:00 UTC")
			assert.NotContains(t, f.Value, "@all", "the comment can't mention everyone")
		}
	}

	// A second silence from the post replaces the first one (same ID).
	out = submit(channelAdmin, postID, map[string]any{"until": "2026-10-26T09:00"})
	assert.Empty(t, out.Error)
	writes = env.am.writes()
	require.Len(t, writes, 2)
	require.NoError(t, json.Unmarshal([]byte(writes[1].Body), &sent))
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", sent.ID)

	// A forged state.
	out = submit(channelAdmin, model.NewId(), map[string]any{"until": "2026-10-25T09:00:00Z"})
	assert.NotEmpty(t, out.Error)
}

func TestParseUntil(t *testing.T) {
	for _, text := range []string{"2026-10-25T09:00:00Z", "2026-10-25T11:00:00+02:00", "2026-10-25T09:00:00", "2026-10-25T09:00", "2026-10-25 09:00"} {
		got, err := parseUntil(text)
		require.NoError(t, err, text)
		assert.True(t, got.Equal(time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)), text)
	}
	_, err := parseUntil("tomorrow")
	assert.Error(t, err)
}
