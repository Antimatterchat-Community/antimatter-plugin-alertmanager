// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	statusFiring   = "firing"
	statusResolved = "resolved"

	// postPropGroup marks the app's alert posts.
	postPropGroup = "alertmanager_group"

	// maxShownAlerts is how many alerts a post lists.
	maxShownAlerts = 10

	// The action IDs of the post's buttons (letters and digits only).
	actionSilence1h    = "silence1h"
	actionSilence4h    = "silence4h"
	actionSilenceUntil = "silenceuntil"
	actionExpire       = "expire"

	timeLayout = "2006-01-02 15:04 MST"
)

// severityColour gives the card colour of a group.
func severityColour(status, severity string) string {
	if status == statusResolved {
		return "good"
	}
	switch strings.ToLower(severity) {
	case "critical", "error", "page", "high", "disaster":
		return "danger"
	case "warning", "warn", "medium", "average":
		return "warning"
	case "info", "informational", "low":
		return "#3f84e5"
	}
	return "#8b8f97"
}

// safeText neutralises what could notify people or pass for Slack's markup in text that comes from alerts: @-mentions
// and <!channel>-style tokens.
func safeText(text string, limit int) string {
	text = strings.ReplaceAll(text, "@", "@\u200b")
	text = strings.ReplaceAll(text, "<!", "<\u200b!")
	return truncateRunes(strings.TrimSpace(text), limit)
}

// safeLink gives an http(s) link, or "" for anything else.
func safeLink(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

// alertTarget names what an alert is about: its instance label, else its job, else nothing.
func alertTarget(labels map[string]string) string {
	for _, name := range []string{"instance", "job"} {
		if v := labels[name]; v != "" {
			return v
		}
	}
	return ""
}

// groupSeverity gives the highest severity among the group's firing alerts (or all, once resolved).
func groupSeverity(rec *groupRecord) string {
	if s := rec.CommonLabels["severity"]; s != "" {
		return s
	}
	rank := map[string]int{"danger": 3, "warning": 2, "#3f84e5": 1}
	best, bestRank := "", -1
	for _, a := range rec.Alerts {
		s := a.Labels["severity"]
		if r := rank[severityColour(statusFiring, s)]; r > bestRank && s != "" {
			best, bestRank = s, r
		}
	}
	return best
}

// groupName gives the alert name of a group.
func groupName(rec *groupRecord) string {
	for _, labels := range []map[string]string{rec.CommonLabels, rec.GroupLabels} {
		if v := labels["alertname"]; v != "" {
			return v
		}
	}
	names := map[string]bool{}
	for _, a := range rec.Alerts {
		if v := a.Labels["alertname"]; v != "" {
			names[v] = true
		}
	}
	list := slices.Sorted(maps.Keys(names))
	if len(list) == 0 {
		return "Alert"
	}
	return strings.Join(list, ", ")
}

func statusTitle(status string) string {
	if status == statusResolved {
		return "Resolved"
	}
	return "Firing"
}

// renderAlert gives the lines of one alert.
func renderAlert(a alertView, showName bool) string {
	var head []string
	if showName && a.Labels["alertname"] != "" {
		head = append(head, "**"+safeText(a.Labels["alertname"], 100)+"**")
	}
	if target := alertTarget(a.Labels); target != "" {
		head = append(head, "`"+strings.ReplaceAll(safeText(target, 100), "`", "'")+"`")
	}
	if a.Status == statusResolved {
		head = append(head, "resolved")
	}
	var lines []string
	if len(head) > 0 {
		lines = append(lines, strings.Join(head, " · "))
	}
	if summary := a.Annotations["summary"]; summary != "" {
		lines = append(lines, safeText(summary, 300))
	}
	if description := a.Annotations["description"]; description != "" {
		lines = append(lines, safeText(description, 600))
	}
	var meta []string
	if started := formatTime(a.StartsAt); started != "" {
		meta = append(meta, "Started "+started)
	}
	if a.Status == statusResolved {
		if ended := formatTime(a.EndsAt); ended != "" {
			meta = append(meta, "ended "+ended)
		}
	}
	if link := safeLink(a.GeneratorURL); link != "" {
		meta = append(meta, "[Source]("+link+")")
	}
	if len(meta) > 0 {
		lines = append(lines, "_"+strings.Join(meta, " · ")+"_")
	}
	return strings.Join(lines, "\n")
}

// renderGroupPost gives the post of a group: its card, with the buttons the group's state calls for.
func renderGroupPost(pluginID string, rec *groupRecord, now time.Time) *model.Post {
	name := groupName(rec)
	severity := groupSeverity(rec)
	title := statusTitle(rec.Status) + ": " + safeText(name, 120)
	if rec.AlertCount > 1 {
		title = fmt.Sprintf("%s (%d): %s", statusTitle(rec.Status), rec.AlertCount, safeText(name, 120))
	}

	showNames := strings.Contains(name, ", ")
	var blocks []string
	for n, a := range rec.Alerts {
		if n == maxShownAlerts {
			break
		}
		blocks = append(blocks, renderAlert(a, showNames))
	}
	if more := rec.AlertCount - min(len(rec.Alerts), maxShownAlerts); more > 0 {
		blocks = append(blocks, fmt.Sprintf("_and %d more_", more))
	}

	attachment := &model.MessageAttachment{
		Fallback: title,
		Color:    severityColour(rec.Status, severity),
		Title:    title,
		Text:     strings.Join(blocks, "\n\n"),
		Footer:   "Alertmanager · " + rec.Instance,
	}
	if len(rec.Alerts) > 0 {
		attachment.TitleLink = safeLink(rec.Alerts[0].GeneratorURL)
	}
	if severity != "" {
		attachment.Fields = append(attachment.Fields, &model.MessageAttachmentField{Title: "Severity", Value: safeText(severity, 40), Short: true})
	}
	if target := alertTarget(rec.CommonLabels); target != "" {
		attachment.Fields = append(attachment.Fields, &model.MessageAttachmentField{Title: "Instance", Value: safeText(target, 100), Short: true})
	}
	silence := rec.activeSilence(now)
	if silence != nil {
		value := fmt.Sprintf("By @%s until %s", silence.ByName, formatTime(silence.Until))
		if silence.Comment != "" {
			value += ": " + safeText(silence.Comment, 200)
		}
		attachment.Fields = append(attachment.Fields, &model.MessageAttachmentField{Title: "Silenced", Value: value})
	}
	attachment.Actions = groupActions(pluginID, rec, silence != nil)

	post := &model.Post{
		Id:        rec.PostID,
		ChannelId: rec.ChannelID,
		Message:   "",
	}
	model.ParseMessageAttachment(post, []*model.MessageAttachment{attachment})
	post.AddProp(postPropGroup, true)
	return post
}

// groupActions gives the buttons of a group's post: the silences while it fires and isn't silenced, and the expiry
// of its silence while there's one.
func groupActions(pluginID string, rec *groupRecord, silenced bool) []*model.PostAction {
	actionURL := "/plugins/" + pluginID + "/action"
	button := func(id, name, style string, context map[string]any) *model.PostAction {
		return &model.PostAction{
			Id:          id,
			Type:        model.PostActionTypeButton,
			Name:        name,
			Style:       style,
			Integration: &model.PostActionIntegration{URL: actionURL, Context: context},
		}
	}
	if silenced {
		return []*model.PostAction{button(actionExpire, "Expire silence", "default", map[string]any{"action": "expire"})}
	}
	if rec.Status != statusFiring {
		return nil
	}
	return []*model.PostAction{
		button(actionSilence1h, "Silence 1h", "default", map[string]any{"action": "silence", "duration": "1h"}),
		button(actionSilence4h, "Silence 4h", "default", map[string]any{"action": "silence", "duration": "4h"}),
		button(actionSilenceUntil, "Silence until…", "default", map[string]any{"action": "silence_until"}),
	}
}
