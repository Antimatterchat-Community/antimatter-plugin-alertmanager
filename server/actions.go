// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	maxActionBody = 64 << 10
	// maxSilence is the longest silence the app sets.
	maxSilence = 30 * 24 * time.Hour
	minSilence = time.Minute

	maxCommentRunes = 500

	dialogCallbackSilenceUntil = "silence_until"
)

// The durations of the post's silence buttons.
var buttonDurations = map[string]time.Duration{"1h": time.Hour, "4h": 4 * time.Hour}

var (
	errNotAlertPost     = errors.New("this isn't an alert post of the Alertmanager app")
	errInstanceGone     = errors.New("the Alertmanager instance of this alert isn't configured any more")
	errNothingToMatch   = errors.New("this alert group has no labels to silence it by")
	errNoGroupSilence   = errors.New("this alert isn't silenced from here")
	errSilenceTooShort  = fmt.Errorf("a silence must last at least %s", minSilence)
	errSilenceTooLong   = errors.New("a silence can last 30 days at most")
	errUnknownAction    = errors.New("unknown action")
	errAlertmanagerFail = errors.New("the Alertmanager instance refused or didn't answer; try again later")
)

// actionTarget is an alert post someone acts on, checked.
type actionTarget struct {
	settings *settings
	inst     *instance
	user     *model.User
	post     *model.Post
	rec      *groupRecord
	key      string
}

// loadActionTarget checks an action on an alert post: the post is one of the app's, its group is known in that very
// channel, the instance is still configured, and the person may silence alerts there.
func (p *Plugin) loadActionTarget(userID, postID string) (*actionTarget, error) {
	if !model.IsValidId(postID) {
		return nil, errNotAlertPost
	}
	post, appErr := p.API.GetPost(postID)
	if appErr != nil || post == nil || post.UserId != p.botID || post.DeleteAt != 0 {
		return nil, errNotAlertPost
	}
	rec, key, err := p.store.groupForPost(post.Id)
	if err != nil || rec == nil || rec.ChannelID != post.ChannelId {
		return nil, errNotAlertPost
	}
	s := p.getSettings()
	inst := s.instances[rec.Instance]
	if inst == nil {
		return nil, errInstanceGone
	}
	if err := p.checkSilenceRight(s, userID, post.ChannelId); err != nil {
		return nil, err
	}
	user, appErr := p.API.GetUser(userID)
	if appErr != nil || user == nil {
		return nil, errNoSilence
	}
	return &actionTarget{settings: s, inst: inst, user: user, post: post, rec: rec, key: key}, nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func ephemeral(w http.ResponseWriter, text string) {
	writeJSON(w, &model.PostActionIntegrationResponse{EphemeralText: text})
}

// requestUserID gives the person the server verified for a request it routes to the app, or "".
func requestUserID(r *http.Request) string {
	return r.Header.Get("Mattermost-User-Id")
}

// handleAction runs a button of an alert post. The server routes the click here with the person's ID in the
// Mattermost-User-Id header; nothing of the request body is trusted beyond naming the post and the button.
func (p *Plugin) handleAction(w http.ResponseWriter, r *http.Request) {
	userID := requestUserID(r)
	if userID == "" {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req model.PostActionIntegrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxActionBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	target, err := p.loadActionTarget(userID, req.PostId)
	if err != nil {
		ephemeral(w, capitalise(err.Error())+".")
		return
	}
	action, _ := req.Context["action"].(string)
	now := p.now()
	switch action {
	case "silence":
		durationName, _ := req.Context["duration"].(string)
		duration, ok := buttonDurations[durationName]
		if !ok {
			ephemeral(w, "Unknown silence.")
			return
		}
		if err := p.silenceGroup(r.Context(), target, now.Add(duration), ""); err != nil {
			ephemeral(w, capitalise(err.Error())+".")
			return
		}
		writeJSON(w, &model.PostActionIntegrationResponse{})
	case "silence_until":
		if err := p.openSilenceDialog(req.TriggerId, target); err != nil {
			ephemeral(w, "The silence dialog couldn't be opened.")
			return
		}
		writeJSON(w, &model.PostActionIntegrationResponse{})
	case "expire":
		if err := p.expireGroupSilence(r.Context(), target); err != nil {
			ephemeral(w, capitalise(err.Error())+".")
			return
		}
		writeJSON(w, &model.PostActionIntegrationResponse{})
	default:
		ephemeral(w, "Unknown action.")
	}
}

func capitalise(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func (p *Plugin) openSilenceDialog(triggerID string, target *actionTarget) error {
	if triggerID == "" {
		return errUnknownAction
	}
	name := groupName(target.rec)
	appErr := p.API.OpenInteractiveDialog(model.OpenDialogRequest{
		TriggerId: triggerID,
		URL:       "/plugins/" + manifest.Id + "/dialog",
		Dialog: model.Dialog{
			CallbackId:       dialogCallbackSilenceUntil,
			Title:            "Silence until…",
			IntroductionText: "Silence " + safeText(name, 120) + " until the time you choose (at most 30 days from now).",
			SubmitLabel:      "Silence",
			State:            target.post.Id,
			Elements: []model.DialogElement{
				{
					DisplayName: "Until",
					Name:        "until",
					Type:        "datetime",
					HelpText:    "When the silence ends.",
					DateTimeConfig: &model.DialogDateTimeConfig{
						MinDate:      "today",
						MaxDate:      "+30d",
						TimeInterval: 30,
					},
				},
				{
					DisplayName: "Comment",
					Name:        "comment",
					Type:        "textarea",
					Optional:    true,
					MaxLength:   maxCommentRunes,
					Placeholder: "Why the alert is silenced",
				},
			},
		},
	})
	if appErr != nil {
		return appErr
	}
	return nil
}

// handleDialog takes the "Silence until…" dialog. Its state names the post and is checked like a click.
func (p *Plugin) handleDialog(w http.ResponseWriter, r *http.Request) {
	userID := requestUserID(r)
	if userID == "" {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	var req model.SubmitDialogRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxActionBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Cancelled {
		w.WriteHeader(http.StatusOK)
		return
	}
	if req.CallbackId != dialogCallbackSilenceUntil {
		writeJSON(w, &model.SubmitDialogResponse{Error: "Unknown dialog."})
		return
	}
	target, err := p.loadActionTarget(userID, req.State)
	if err != nil {
		writeJSON(w, &model.SubmitDialogResponse{Error: capitalise(err.Error()) + "."})
		return
	}
	now := p.now()
	untilText, _ := req.Submission["until"].(string)
	until, err := parseUntil(untilText)
	if err != nil {
		writeJSON(w, &model.SubmitDialogResponse{Errors: map[string]string{"until": "Choose a date and time."}})
		return
	}
	if err := checkSilenceLength(until.Sub(now)); err != nil {
		writeJSON(w, &model.SubmitDialogResponse{Errors: map[string]string{"until": capitalise(err.Error()) + "."}})
		return
	}
	comment, _ := req.Submission["comment"].(string)
	if err := p.silenceGroup(r.Context(), target, until, truncateRunes(strings.TrimSpace(comment), maxCommentRunes)); err != nil {
		writeJSON(w, &model.SubmitDialogResponse{Error: capitalise(err.Error()) + "."})
		return
	}
	writeJSON(w, &model.SubmitDialogResponse{})
}

// parseUntil reads the dialog's date and time; one without a time zone is taken as UTC.
func parseUntil(text string) (time.Time, error) {
	text = strings.TrimSpace(text)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("not a date and time")
}

func checkSilenceLength(d time.Duration) error {
	switch {
	case d < minSilence:
		return errSilenceTooShort
	case d > maxSilence:
		return errSilenceTooLong
	}
	return nil
}

// groupMatchers gives the matchers of a silence of a group: its group labels, with its alert name and instance when
// all its alerts share them. They're all equality matchers, so the silence matches that group's alerts only.
func groupMatchers(rec *groupRecord) []amMatcher {
	labels := maps.Clone(rec.GroupLabels)
	if labels == nil {
		labels = map[string]string{}
	}
	for _, name := range []string{"alertname", "instance"} {
		if v := rec.CommonLabels[name]; v != "" {
			labels[name] = v
		}
	}
	var out []amMatcher
	for _, name := range slices.Sorted(maps.Keys(labels)) {
		if labels[name] == "" {
			continue
		}
		equal := true
		out = append(out, amMatcher{Name: name, Value: labels[name], IsEqual: &equal})
	}
	return out
}

// silenceGroup silences a group until a time (replacing the silence set from its post, if any), and shows it on the
// post.
func (p *Plugin) silenceGroup(ctx context.Context, target *actionTarget, until time.Time, comment string) error {
	unlock := p.groupLocks.lock(target.key)
	defer unlock()
	rec, err := p.store.getGroup(target.key)
	if err != nil || rec == nil || rec.PostID != target.post.Id {
		return errNotAlertPost
	}
	matchers := groupMatchers(rec)
	if len(matchers) == 0 {
		return errNothingToMatch
	}
	now := p.now()
	amComment := comment
	if amComment == "" {
		amComment = "Silenced from Antimatter"
	}
	silence := &amPostableSilence{
		Matchers:  matchers,
		StartsAt:  now.UTC(),
		EndsAt:    until.UTC(),
		CreatedBy: "@" + target.user.Username,
		Comment:   amComment,
	}
	if active := rec.activeSilence(now); active != nil {
		silence.ID = active.ID
	}
	ctx, cancel := context.WithTimeout(ctx, alertmanagerTimeout)
	defer cancel()
	id, err := target.inst.createSilence(ctx, silence)
	if err != nil {
		p.API.LogWarn("Alertmanager: a silence couldn't be created", "instance", target.inst.name,
			"error", target.settings.redact(err.Error()))
		return errAlertmanagerFail
	}
	rec.Silence = &silenceRecord{ID: id, ByUserID: target.user.Id, ByName: target.user.Username, Until: until.UTC(), Comment: comment}
	if err := p.store.saveGroup(target.key, rec); err != nil {
		return err
	}
	if err := p.store.saveSilenceIndex(rec.Instance, id, &silenceIndex{ChannelID: rec.ChannelID, GroupKey: target.key}, until, now); err != nil {
		p.API.LogWarn("Alertmanager: a silence couldn't be recorded", "instance", rec.Instance, "error", err.Error())
	}
	p.refreshPost(rec, now)
	p.reply(rec, fmt.Sprintf("Silenced by @%s until %s.", target.user.Username, formatTime(until)))
	return nil
}

// expireGroupSilence expires the silence set from a group's post.
func (p *Plugin) expireGroupSilence(ctx context.Context, target *actionTarget) error {
	unlock := p.groupLocks.lock(target.key)
	defer unlock()
	rec, err := p.store.getGroup(target.key)
	if err != nil || rec == nil || rec.PostID != target.post.Id {
		return errNotAlertPost
	}
	if rec.Silence == nil {
		return errNoGroupSilence
	}
	ctx, cancel := context.WithTimeout(ctx, alertmanagerTimeout)
	defer cancel()
	if err := target.inst.expireSilence(ctx, rec.Silence.ID); err != nil && !isNotFound(err) {
		p.API.LogWarn("Alertmanager: a silence couldn't be expired", "instance", target.inst.name,
			"error", target.settings.redact(err.Error()))
		return errAlertmanagerFail
	}
	rec.Silence = nil
	if err := p.store.saveGroup(target.key, rec); err != nil {
		return err
	}
	now := p.now()
	p.refreshPost(rec, now)
	p.reply(rec, fmt.Sprintf("Silence expired by @%s.", target.user.Username))
	return nil
}

func isNotFound(err error) bool {
	var amErr *amError
	return errors.As(err, &amErr) && amErr.Status == http.StatusNotFound
}

// refreshPost shows a group's record on its post.
func (p *Plugin) refreshPost(rec *groupRecord, now time.Time) {
	post := renderGroupPost(manifest.Id, rec, now)
	post.UserId = p.botID
	if _, appErr := p.API.UpdatePost(post); appErr != nil {
		p.API.LogWarn("Alertmanager: an alert post couldn't be updated", "instance", rec.Instance, "error", appErr.Error())
	}
}
