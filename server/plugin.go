// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// Plugin is the Alertmanager app.
type Plugin struct {
	plugin.MattermostPlugin

	configurationLock sync.RWMutex
	settings          *settings

	store      *Store
	botID      string
	limiter    *rateLimiter
	groupLocks keyedMutex

	// now gives the time; replaced in tests.
	now func() time.Time
}

// OnActivate starts the app: its bot and its tools.
func (p *Plugin) OnActivate() error {
	if p.now == nil {
		p.now = time.Now
	}
	p.store = &Store{api: p.API}
	p.limiter = newRateLimiter(webhookBurst, webhookRate)

	botID, err := p.API.EnsureBotUser(&model.Bot{
		Username:    "alertmanager",
		DisplayName: "Alertmanager",
		Description: "Posts the alerts of Alertmanager.",
	})
	if err != nil {
		return fmt.Errorf("failed to ensure the Alertmanager bot: %w", err)
	}
	p.botID = botID

	if appErr := p.API.RegisterAITools(aiToolDefinitions()); appErr != nil {
		// Servers without agents' tools still get the alerts.
		p.API.LogWarn("Alertmanager: the agents' tools couldn't be registered", "error", appErr.Error())
	}
	return nil
}

// ServeHTTP serves the webhook, and the buttons and dialog of the alert posts.
func (p *Plugin) ServeHTTP(_ *plugin.Context, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/webhook/"):
		parts := strings.Split(strings.TrimPrefix(path, "/webhook/"), "/")
		if r.Method != http.MethodPost || len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		p.handleWebhook(w, r, parts[0], parts[1])
	case path == "/action" && r.Method == http.MethodPost:
		p.handleAction(w, r)
	case path == "/dialog" && r.Method == http.MethodPost:
		p.handleDialog(w, r)
	default:
		http.NotFound(w, r)
	}
}
