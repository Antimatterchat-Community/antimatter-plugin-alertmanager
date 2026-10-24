// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Who may silence alerts (setting SilencePermission).
const (
	silenceByChannelAdmins  = "channel_admins"
	silenceByChannelPosters = "channel_posters"
	silenceBySystemAdmins   = "system_admins"
)

const (
	// minWebhookSecretLength keeps webhook secrets out of reach of guessing.
	minWebhookSecretLength = 24
	maxWebhookSecretLength = 256
	maxInstances           = 32
	maxRoutesPerInstance   = 64
)

var (
	instanceNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	webhookSecretPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// configuration is the app's settings as the server keeps them (plugin.json).
type configuration struct {
	Instances         string
	InstanceSecrets   string
	SilencePermission string
	PostSeverityNone  bool
}

// instanceConfig is one entry of the Instances setting.
type instanceConfig struct {
	Name   string        `json:"name"`
	URL    string        `json:"url"`
	Routes []routeConfig `json:"routes"`
}

// routeConfig maps an Alertmanager receiver to a channel, by community and channel name or by channel ID.
type routeConfig struct {
	Receiver  string `json:"receiver"`
	Team      string `json:"team,omitempty"`
	Channel   string `json:"channel,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
}

// instanceSecretConfig is one entry of the InstanceSecrets setting.
type instanceSecretConfig struct {
	WebhookSecret string `json:"webhook_secret"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	BearerToken   string `json:"bearer_token"`
}

// instance is a configured Alertmanager, ready to use.
type instance struct {
	name    string
	baseURL *url.URL
	routes  []routeConfig

	// webhookSecretHash is the SHA-256 of the webhook secret: comparing hashes takes the same time whatever the
	// length of the secret tried.
	webhookSecretHash [sha256.Size]byte

	authHeader string
	client     *http.Client
}

// settings is the parsed configuration.
type settings struct {
	instances         map[string]*instance
	names             []string
	silencePermission string
	postSeverityNone  bool
	// secrets are every secret value of the configuration, to redact from anything logged or answered.
	secrets []string
}

// dummySecretHash is compared against when the instance is unknown, so that an unknown instance and a wrong secret
// take the same time.
var dummySecretHash = sha256.Sum256([]byte("no instance"))

// checkWebhookSecret compares a webhook secret with the instance's in constant time. A nil instance never matches.
func (i *instance) checkWebhookSecret(given string) bool {
	want := dummySecretHash
	if i != nil {
		want = i.webhookSecretHash
	}
	got := sha256.Sum256([]byte(given))
	match := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	return match && i != nil
}

// routesFor gives the routes of a receiver.
func (i *instance) routesFor(receiver string) []routeConfig {
	var out []routeConfig
	for _, r := range i.routes {
		if r.Receiver == receiver {
			out = append(out, r)
		}
	}
	return out
}

// parseSettings reads the configuration. Instances that aren't valid are left out; the problems are returned, without
// any secret in them.
func parseSettings(c *configuration) (*settings, []string) {
	s := &settings{
		instances:         map[string]*instance{},
		silencePermission: parseSilencePermission(c.SilencePermission),
		postSeverityNone:  c.PostSeverityNone,
	}
	var problems []string

	var configs []instanceConfig
	if text := strings.TrimSpace(c.Instances); text != "" {
		decoder := json.NewDecoder(strings.NewReader(text))
		// Unknown fields are refused: a secret put here by mistake would be shown in the System Console.
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&configs); err != nil {
			return s, []string{"the Alertmanager instances setting isn't a valid JSON list of instances: " + err.Error()}
		}
	}
	secrets := map[string]instanceSecretConfig{}
	if text := strings.TrimSpace(c.InstanceSecrets); text != "" {
		// The error of a secret setting isn't shown: it may quote it.
		if err := json.Unmarshal([]byte(text), &secrets); err != nil {
			return s, []string{"the instance secrets setting isn't a valid JSON object of instance names"}
		}
	}
	for _, secret := range secrets {
		s.secrets = appendSecrets(s.secrets, secret)
	}
	if len(configs) > maxInstances {
		problems = append(problems, fmt.Sprintf("only the first %d Alertmanager instances are used", maxInstances))
		configs = configs[:maxInstances]
	}

	for n, ic := range configs {
		label := fmt.Sprintf("instance %d", n+1)
		if !instanceNamePattern.MatchString(ic.Name) {
			problems = append(problems, label+": the name must be 1 to 64 letters, digits, \"-\" or \"_\"")
			continue
		}
		label = fmt.Sprintf("instance %q", ic.Name)
		if _, taken := s.instances[ic.Name]; taken {
			problems = append(problems, label+": the name is used twice")
			continue
		}
		inst, problem := buildInstance(ic, secrets[ic.Name])
		if problem != "" {
			problems = append(problems, label+": "+problem)
			continue
		}
		s.instances[ic.Name] = inst
		s.names = append(s.names, ic.Name)
	}
	for name := range secrets {
		if _, ok := s.instances[name]; !ok && !slices.ContainsFunc(configs, func(ic instanceConfig) bool { return ic.Name == name }) {
			problems = append(problems, fmt.Sprintf("the instance secrets name %q, which isn't an instance", name))
		}
	}
	slices.Sort(problems)
	return s, problems
}

func appendSecrets(list []string, sc instanceSecretConfig) []string {
	for _, v := range []string{sc.WebhookSecret, sc.Password, sc.BearerToken} {
		if v != "" {
			list = append(list, v)
		}
	}
	if sc.Username != "" || sc.Password != "" {
		list = append(list, basicAuthValue(sc.Username, sc.Password))
	}
	return list
}

func basicAuthValue(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func parseSilencePermission(value string) string {
	switch value {
	case "", silenceByChannelAdmins:
		return silenceByChannelAdmins
	case silenceByChannelPosters, silenceBySystemAdmins:
		return value
	}
	// An unknown value gives the strictest choice.
	return silenceBySystemAdmins
}

func buildInstance(ic instanceConfig, sc instanceSecretConfig) (*instance, string) {
	base, err := url.Parse(strings.TrimSpace(ic.URL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, "the url must be an http or https address"
	}
	if base.User != nil {
		return nil, "the url must not hold a user name or password: put them in the instance secrets"
	}
	if base.RawQuery != "" || base.Fragment != "" {
		return nil, "the url must not have a query or fragment"
	}
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawPath = ""

	switch {
	case sc.WebhookSecret == "":
		return nil, "it has no webhook secret in the instance secrets"
	case len(sc.WebhookSecret) < minWebhookSecretLength || len(sc.WebhookSecret) > maxWebhookSecretLength:
		return nil, fmt.Sprintf("its webhook secret must be %d to %d characters long", minWebhookSecretLength, maxWebhookSecretLength)
	case !webhookSecretPattern.MatchString(sc.WebhookSecret):
		return nil, "its webhook secret may only hold letters, digits and . _ ~ -"
	}

	inst := &instance{
		name:              ic.Name,
		baseURL:           base,
		webhookSecretHash: sha256.Sum256([]byte(sc.WebhookSecret)),
	}
	switch {
	case sc.BearerToken != "" && (sc.Username != "" || sc.Password != ""):
		return nil, "use either basic auth or a bearer token, not both"
	case sc.BearerToken != "":
		inst.authHeader = "Bearer " + sc.BearerToken
	case sc.Username != "" || sc.Password != "":
		inst.authHeader = "Basic " + basicAuthValue(sc.Username, sc.Password)
	}

	if len(ic.Routes) > maxRoutesPerInstance {
		return nil, fmt.Sprintf("it has more than %d routes", maxRoutesPerInstance)
	}
	for n, r := range ic.Routes {
		r.Receiver = strings.TrimSpace(r.Receiver)
		r.Team = strings.TrimSpace(r.Team)
		r.Channel = strings.TrimSpace(r.Channel)
		r.ChannelID = strings.TrimSpace(r.ChannelID)
		switch {
		case r.Receiver == "":
			return nil, fmt.Sprintf("route %d has no receiver", n+1)
		case r.ChannelID != "" && (r.Team != "" || r.Channel != ""):
			return nil, fmt.Sprintf("route %d names its channel twice: use either channel_id or team and channel", n+1)
		case r.ChannelID == "" && (r.Team == "" || r.Channel == ""):
			return nil, fmt.Sprintf("route %d needs a channel_id, or a team and a channel", n+1)
		}
		inst.routes = append(inst.routes, r)
	}
	inst.client = newAlertmanagerHTTPClient()
	return inst, ""
}

// redact removes every secret of the configuration from a text.
func (s *settings) redact(text string) string {
	if s == nil {
		return text
	}
	for _, secret := range s.secrets {
		if len(secret) >= 4 {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}

// getSettings gives the current settings; they're never changed once set.
func (p *Plugin) getSettings() *settings {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	if p.settings == nil {
		return &settings{instances: map[string]*instance{}, silencePermission: silenceByChannelAdmins}
	}
	return p.settings
}

func (p *Plugin) setSettings(s *settings) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()
	p.settings = s
}

// OnConfigurationChange reads the settings. Problems are logged (never with a secret) and leave the faulty instances
// out, so that a mistake in one instance doesn't stop the others.
func (p *Plugin) OnConfigurationChange() error {
	c := new(configuration)
	if err := p.API.LoadPluginConfiguration(c); err != nil {
		return fmt.Errorf("failed to load the app's settings: %w", err)
	}
	s, problems := parseSettings(c)
	for _, problem := range problems {
		p.API.LogWarn("Alertmanager settings: "+s.redact(problem), "instances", len(s.names))
	}
	p.setSettings(s)
	return nil
}
