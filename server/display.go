// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// toolDisplayResult is what list_alerts and list_silences give back to the assistant: message
// attachments in the same format the app's own alert posts use (render.go's
// model.MessageAttachment), plus a plain-text summary for the assistant card's subtitle and
// screen readers. The action tools (create_silence, expire_silence) keep their own plain
// confirmation shape (silenceResult in tools.go): they report what was done, not something to
// show as a card.
type toolDisplayResult struct {
	Attachments []*model.MessageAttachment `json:"attachments"`
	Summary     string                     `json:"summary"`
}

const (
	// maxShownAlertAttachments is the most alert attachments list_alerts returns before a final
	// "+N more" attachment, keeping a result with many matches well under the assistant's 64 KiB
	// result cap.
	maxShownAlertAttachments = 10

	alertStateSilenced  = "silenced"
	alertStateInhibited = "inhibited"
)

// alertDisplayState gives one alert's state for list_alerts and its attachment's colour:
// "silenced" or "inhibited" when something is actively doing that to it now, "resolved" once its
// own end time has passed, and "firing" otherwise (Alertmanager's raw status.state is "active" or
// "unprocessed" for every alert still in its active list, which this app always shows as firing).
func alertDisplayState(a amAlert, now time.Time) string {
	switch {
	case len(a.Status.SilencedBy) > 0:
		return alertStateSilenced
	case len(a.Status.InhibitedBy) > 0:
		return alertStateInhibited
	case !a.EndsAt.IsZero() && a.EndsAt.Before(now):
		return statusResolved
	default:
		return statusFiring
	}
}

// toolAlertColour gives one list_alerts attachment's colour: the same colours the app's own alert
// posts use (render.go's severityColour) for a firing alert's severity, green once resolved, and
// the neutral grey severityColour itself gives an unlabelled severity for a silenced or inhibited
// alert (being silenced or inhibited is a state of the alert, not a severity, so it never takes a
// severity colour).
func toolAlertColour(state, severity string) string {
	switch state {
	case statusResolved:
		return "good"
	case alertStateSilenced, alertStateInhibited:
		return "#8b8f97"
	default:
		return severityColour(statusFiring, severity)
	}
}

// alertAttachment builds one list_alerts attachment for a: state (passed in, from
// alertDisplayState), severity (its label, defaulting to "info" when it has none), target (its
// instance, or job), summary (its annotations) and its generator link, http(s) only (safeLink
// drops anything else).
func alertAttachment(a amAlert, state, instanceName string) *model.MessageAttachment {
	severity := strings.ToLower(a.Labels["severity"])
	if severity == "" {
		severity = "info"
	}
	title := a.Labels["alertname"]
	if title == "" {
		title = "Alert"
	}
	att := &model.MessageAttachment{
		Fallback:  title + ": " + state,
		Color:     toolAlertColour(state, severity),
		Title:     title,
		TitleLink: safeLink(a.GeneratorURL),
		Text:      safeText(a.Annotations["summary"], maxToolTextRunes),
		Footer:    "Alertmanager",
		Fields:    []*model.MessageAttachmentField{{Title: "Severity", Value: severity, Short: true}},
	}
	if target := alertTarget(a.Labels); target != "" {
		att.Fields = append(att.Fields, &model.MessageAttachmentField{Title: "Target", Value: safeText(target, 100), Short: true})
	}
	if since := formatTime(a.StartsAt); since != "" {
		att.Fields = append(att.Fields, &model.MessageAttachmentField{Title: "Since", Value: since, Short: true})
	}
	if instanceName != "" {
		att.Fields = append(att.Fields, &model.MessageAttachmentField{Title: "Instance", Value: instanceName, Short: true})
	}
	return att
}

// noAlertsText gives list_alerts' empty-result text: scoped to the one instance asked for or
// looked at, when there is one.
func noAlertsText(scopeName string) string {
	if scopeName == "" {
		return "No alerts."
	}
	return "No alerts for " + scopeName + "."
}

// moreAttachment gives the trailing "+N more" attachment a list tool adds once its own items
// exceed what it shows as full attachments.
func moreAttachment(n int, noun string) *model.MessageAttachment {
	text := fmt.Sprintf("+%d more %s", n, noun)
	return &model.MessageAttachment{Fallback: text, Text: text}
}

// noItemsAttachment gives the single calm attachment a list tool returns when nothing matched:
// green, like a resolved alert, so an empty result doesn't read as a problem.
func noItemsAttachment(text string) *model.MessageAttachment {
	return &model.MessageAttachment{Fallback: text, Color: "good", Text: text}
}

// markdownTable renders rows under header as a markdown table, for list_silences' attachment
// text.
func markdownTable(header []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString("| " + strings.Join(header, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat(" --- |", len(header)) + "\n")
	for _, row := range rows {
		b.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
