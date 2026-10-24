// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	// maxWebhookBody caps a webhook's body. Alertmanager's own default caps nothing; 1 MiB holds several hundred alerts.
	maxWebhookBody = 1 << 20
	// The webhook rate limit of each instance: a burst of webhookBurst, refilled at webhookRate a second.
	webhookBurst = 60
	webhookRate  = 2.0
)

// webhookPayload is Alertmanager's webhook (version 4).
type webhookPayload struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []webhookAlert    `json:"alerts"`
}

type webhookAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// rateLimiter is a token bucket per instance.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   float64
	rate    float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(burst int, rate float64) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, burst: float64(burst), rate: rate}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// logValue makes a value from a webhook safe and short for a log line.
func logValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	return truncateRunes(value, 100)
}

// handleWebhook takes a webhook of Alertmanager. An unknown instance and a wrong secret get the same 404; the path,
// which holds the secret, is never logged.
func (p *Plugin) handleWebhook(w http.ResponseWriter, r *http.Request, instanceName, secret string) {
	s := p.getSettings()
	inst := s.instances[instanceName]
	if !inst.checkWebhookSecret(secret) {
		http.NotFound(w, r)
		return
	}
	if !p.limiter.allow(inst.name, p.now()) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var payload webhookPayload
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err := decoder.Decode(&payload); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "the body isn't an Alertmanager webhook", http.StatusBadRequest)
		return
	}
	if payload.Version != "4" || payload.GroupKey == "" || payload.Receiver == "" {
		http.Error(w, "the body isn't an Alertmanager webhook of version 4", http.StatusBadRequest)
		return
	}

	routes := inst.routesFor(payload.Receiver)
	if len(routes) == 0 {
		p.API.LogInfo("Alertmanager: an alert for a receiver without a route was ignored",
			"instance", inst.name, "receiver", logValue(payload.Receiver))
		w.WriteHeader(http.StatusOK)
		return
	}
	for _, route := range routes {
		channel, err := p.routeChannel(route)
		if err != nil {
			p.API.LogWarn("Alertmanager: the channel of a route wasn't found",
				"instance", inst.name, "receiver", logValue(payload.Receiver))
			continue
		}
		if err := p.postGroup(s, inst, channel, &payload); err != nil {
			p.API.LogError("Alertmanager: an alert couldn't be posted",
				"instance", inst.name, "receiver", logValue(payload.Receiver), "error", s.redact(err.Error()))
			http.Error(w, "the alert couldn't be posted", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// routeChannel finds the channel of a route.
func (p *Plugin) routeChannel(route routeConfig) (*model.Channel, error) {
	var channel *model.Channel
	var appErr *model.AppError
	if route.ChannelID != "" {
		channel, appErr = p.API.GetChannel(route.ChannelID)
	} else {
		channel, appErr = p.API.GetChannelByNameForTeamName(route.Team, route.Channel, false)
	}
	if appErr != nil {
		return nil, appErr
	}
	if channel == nil || channel.DeleteAt != 0 {
		return nil, errors.New("the channel is archived")
	}
	return channel, nil
}

// keptAlerts gives the alerts of a webhook the app posts: without those of severity "none" unless the settings say
// otherwise.
func keptAlerts(alerts []webhookAlert, postSeverityNone bool) []webhookAlert {
	out := make([]webhookAlert, 0, len(alerts))
	for _, a := range alerts {
		if !postSeverityNone && strings.EqualFold(a.Labels["severity"], "none") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// postGroup posts an alert group in a channel, or updates its post. A group that resolves keeps its post, which
// gets a "Resolved" reply; one that fires again after resolving gets a new post.
func (p *Plugin) postGroup(s *settings, inst *instance, channel *model.Channel, payload *webhookPayload) error {
	alerts := keptAlerts(payload.Alerts, s.postSeverityNone)
	if len(alerts) == 0 {
		return nil
	}
	status := statusResolved
	for _, a := range alerts {
		if a.Status == statusFiring {
			status = statusFiring
			break
		}
	}

	key := groupKeyOf(inst.name, channel.Id, payload.GroupKey)
	unlock := p.groupLocks.lock(key)
	defer unlock()

	rec, err := p.store.getGroup(key)
	if err != nil {
		return err
	}
	previous := ""
	if rec != nil {
		previous = rec.Status
	}
	fresh := rec == nil || (previous == statusResolved && status == statusFiring)
	if fresh {
		rec = &groupRecord{Instance: inst.name, ChannelID: channel.Id, GroupKey: payload.GroupKey}
	}
	rec.Receiver = payload.Receiver
	rec.Status = status
	rec.GroupLabels = payload.GroupLabels
	rec.CommonLabels = payload.CommonLabels
	rec.AlertCount = len(alerts)
	if len(alerts) == len(payload.Alerts) {
		rec.AlertCount += payload.TruncatedAlerts
	}
	rec.Alerts = rec.Alerts[:0]
	// Firing alerts first.
	for _, wanted := range []string{statusFiring, statusResolved} {
		for _, a := range alerts {
			if a.Status == wanted && len(rec.Alerts) < maxStoredAlerts {
				rec.Alerts = append(rec.Alerts, alertView{
					Status:       a.Status,
					Labels:       a.Labels,
					Annotations:  pickAnnotations(a.Annotations),
					StartsAt:     a.StartsAt,
					EndsAt:       a.EndsAt,
					GeneratorURL: safeLink(a.GeneratorURL),
				})
			}
		}
	}
	now := p.now()
	rec.UpdatedAt = now.UnixMilli()

	if !fresh {
		post := renderGroupPost(manifest.Id, rec, now)
		post.UserId = p.botID
		if _, appErr := p.API.UpdatePost(post); appErr != nil {
			// The post was deleted: the group gets a new one.
			fresh = true
		}
	}
	if fresh {
		rec.PostID = ""
		post := renderGroupPost(manifest.Id, rec, now)
		post.Id = ""
		post.UserId = p.botID
		created, appErr := p.API.CreatePost(post)
		if appErr != nil {
			return appErr
		}
		rec.PostID = created.Id
	}
	if err := p.store.saveGroup(key, rec); err != nil {
		return err
	}
	if previous == statusFiring && status == statusResolved && !fresh {
		p.reply(rec, "**Resolved:** "+safeText(groupName(rec), 120))
	}
	return nil
}

// pickAnnotations keeps the annotations the post shows.
func pickAnnotations(annotations map[string]string) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"summary", "description"} {
		if v := annotations[name]; v != "" {
			out[name] = truncateRunes(v, 2000)
		}
	}
	return out
}

// reply posts a reply of the bot to a group's post.
func (p *Plugin) reply(rec *groupRecord, message string) {
	if _, appErr := p.API.CreatePost(&model.Post{
		UserId:    p.botID,
		ChannelId: rec.ChannelID,
		RootId:    rec.PostID,
		Message:   message,
	}); appErr != nil {
		p.API.LogWarn("Alertmanager: a reply couldn't be posted", "instance", rec.Instance, "error", appErr.Error())
	}
}
