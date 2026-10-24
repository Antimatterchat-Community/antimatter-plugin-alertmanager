// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Manual checks against a running Alertmanager, skipped unless asked for:
//
//	AM_MANUAL_ALERTS=<file of GET /api/v2/alerts>  posts them as Alertmanager's webhooks would, through the handler;
//	AM_MANUAL_URL=<Alertmanager's address>          runs list_alerts and list_silences against it;
//	AM_MANUAL_SILENCE=1 (with AM_MANUAL_URL)         also creates a silence that matches nothing and expires it.

// webhookPayloadsFromAPI groups alerts of the API as Alertmanager does with group_by [alertname, instance], and makes
// the webhooks of version 4 it would send.
func webhookPayloadsFromAPI(alerts []amAlert) []*webhookPayload {
	byGroup := map[string]*webhookPayload{}
	var keys []string
	for _, a := range alerts {
		groupLabels := map[string]string{}
		var parts []string
		for _, name := range []string{"alertname", "instance"} {
			if v, ok := a.Labels[name]; ok {
				groupLabels[name] = v
				parts = append(parts, name+"="+strconv.Quote(v))
			}
		}
		for _, r := range a.Receivers {
			key := "{}:{" + strings.Join(parts, ", ") + "}"
			id := r.Name + "\x00" + key
			payload := byGroup[id]
			if payload == nil {
				payload = &webhookPayload{
					Version: "4", GroupKey: key, Status: statusFiring, Receiver: r.Name,
					GroupLabels: groupLabels, CommonLabels: a.Labels, CommonAnnotations: a.Annotations,
				}
				byGroup[id] = payload
				keys = append(keys, id)
			}
			payload.Alerts = append(payload.Alerts, webhookAlert{
				Status: statusFiring, Labels: a.Labels, Annotations: a.Annotations, StartsAt: a.StartsAt,
				EndsAt: a.EndsAt, GeneratorURL: a.GeneratorURL, Fingerprint: a.Fingerprint,
			})
		}
	}
	slices.Sort(keys)
	out := make([]*webhookPayload, 0, len(keys))
	for _, k := range keys {
		out = append(out, byGroup[k])
	}
	return out
}

func TestManualCapturedPayload(t *testing.T) {
	path := os.Getenv("AM_MANUAL_ALERTS")
	if path == "" {
		t.Skip("set AM_MANUAL_ALERTS to a file of GET /api/v2/alerts")
	}
	data, err := os.ReadFile(path) //nolint:gosec // a file the developer names
	require.NoError(t, err)
	var alerts []amAlert
	require.NoError(t, json.Unmarshal(data, &alerts))
	payloads := webhookPayloadsFromAPI(alerts)
	require.NotEmpty(t, payloads)

	for _, options := range [][]envOption{nil, {withSeverityNone()}} {
		env := newTestEnv(t, options...)
		for _, payload := range payloads {
			body, _ := json.MarshalIndent(payload, "", "  ")
			t.Logf("webhook:\n%s", body)
			env.postAlert(payload)
		}
		t.Logf("posts with severity none %s: %d", map[bool]string{true: "on", false: "off"}[len(options) > 0], len(env.rootPosts()))
		for _, post := range env.rootPosts() {
			a := attachmentOf(t, post)
			require.NoError(t, a.IsValid())
			t.Logf("card: %s | %s | colour %s | buttons %v\n%s", a.Title, a.TitleLink, a.Color, actionIDs(a), a.Text)
		}
	}
}

func TestManualListAlerts(t *testing.T) {
	url := os.Getenv("AM_MANUAL_URL")
	if url == "" {
		t.Skip("set AM_MANUAL_URL to Alertmanager's address")
	}
	env := newTestEnv(t, withSeverityNone())
	s := env.p.getSettings()
	s.instances["prod"].baseURL = mustURL(t, url)
	s.instances["prod"].authHeader = ""

	for _, tool := range []string{toolListAlerts, toolListSilences} {
		result := env.tool(dbAdmin, tool, map[string]any{})
		require.Empty(t, result.Error, tool)
		t.Logf("%s: %s", tool, result.Text)
	}
}

// TestManualSilenceRoundTrip creates a silence that matches no alert with create_silence and expires it at once
// with expire_silence (AM_MANUAL_URL and AM_MANUAL_SILENCE=1).
func TestManualSilenceRoundTrip(t *testing.T) {
	url := os.Getenv("AM_MANUAL_URL")
	if url == "" || os.Getenv("AM_MANUAL_SILENCE") != "1" {
		t.Skip("set AM_MANUAL_URL and AM_MANUAL_SILENCE=1")
	}
	env := newTestEnv(t)
	env.now = time.Now()
	s := env.p.getSettings()
	s.instances["prod"].baseURL = mustURL(t, url)
	s.instances["prod"].authHeader = ""

	created := env.tool(teamAdmin, toolCreateSilence, map[string]any{
		"matchers": []map[string]any{{"name": "alertname", "value": "AntimatterAppManualCheck"}},
		"duration": "5m",
		"comment":  "Antimatter Alertmanager app: manual check, expired at once",
	})
	require.Empty(t, created.Error)
	t.Logf("create_silence: %s", created.Text)
	var out silenceResult
	require.NoError(t, json.Unmarshal([]byte(created.Text), &out))
	expired := env.tool(teamAdmin, toolExpireSilence, map[string]any{"id": out.ID})
	require.Empty(t, expired.Error)
	t.Logf("expire_silence: %s", expired.Text)
}
