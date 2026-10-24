// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

// The agents' tools. They run for the person the server verified (call.UserId), with that person's rights only:
// alerts are listed for the receivers routed to channels they can read, silences for the instances routed to such a
// channel, and silences are set and expired only by people with the silence right (see checkSilenceRight) in every
// channel the instance is routed to, or, for a silence set from an alert post, in that post's channel. The server
// asks the person to confirm the tools that change something; the rights are checked here all the same.

const (
	toolListAlerts    = "list_alerts"
	toolListSilences  = "list_silences"
	toolCreateSilence = "create_silence"
	toolExpireSilence = "expire_silence"

	toolTimeout      = 60 * time.Second
	maxToolSilences  = 50
	maxToolFilters   = 10
	maxFilterLength  = 200
	maxToolMatchers  = 16
	maxMatcherValue  = 1024
	maxToolTextRunes = 300
)

var labelNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,99}$`)

var (
	errUnknownInstance   = errors.New("there's no Alertmanager instance of that name that you can see")
	errNameInstance      = errors.New("name the Alertmanager instance in the alertmanager argument")
	errUnknownReceiver   = errors.New("there's no receiver of that name that you can see")
	errNoInstanceSilence = errors.New("you may not silence alerts of this Alertmanager instance: it needs the silence right in every channel the instance is routed to")
	errNoSuchSilence     = errors.New("there's no silence with that ID")
	errBadTarget         = errors.New("the target isn't a host or target name")
)

// instanceProperty names the Alertmanager instance a tool works on. It isn't called "instance": the assistant fills
// the properties named like a host (instance, host, target...) with the host a message talks about, such as "www-1"
// in "is www-1 down?", which is never the name of an Alertmanager instance.
const instanceProperty = `"alertmanager": {"type": "string", "description": "The name of the Alertmanager instance (not a host). Optional: the read tools then look at every instance the person can see, and the other tools need it only when there are several."}`

// aiToolDefinitions gives the app's tools.
func aiToolDefinitions() []*model.AIToolDefinition {
	return []*model.AIToolDefinition{
		{
			Name:  toolListAlerts,
			Title: "List alerts",
			Description: "Lists the alerts of Alertmanager (name, instance, severity, state, summary, labels, start) for the " +
				"receivers routed to channels the person can read.",
			Kind: model.AIToolKindRead,
			InputSchema: json.RawMessage(`{"type": "object", "properties": {` + instanceProperty + `,
				"receiver": {"type": "string", "description": "Only the alerts sent to this Alertmanager receiver."},
				"target": {"type": "string", "description": "Only the alerts about this host or target: their instance label, with or without its port, or else their job."},
				"filter": {"type": "array", "items": {"type": "string"}, "description": "Alertmanager label matchers, such as alertname=\"HighCPU\" or instance=~\"www-.*\"."},
				"active": {"type": "boolean", "description": "Include active alerts (default true)."},
				"silenced": {"type": "boolean", "description": "Include silenced alerts (default true)."},
				"inhibited": {"type": "boolean", "description": "Include inhibited alerts (default true)."}
			}, "additionalProperties": false}`),
		},
		{
			Name:        toolListSilences,
			Title:       "List silences",
			Description: "Lists the active and pending silences of Alertmanager: ID, matchers, end, author and comment.",
			Kind:        model.AIToolKindRead,
			InputSchema: json.RawMessage(`{"type": "object", "properties": {` + instanceProperty + `,
				"filter": {"type": "array", "items": {"type": "string"}, "description": "Only silences whose matchers match these label matchers, such as alertname=\"HighCPU\"."}
			}, "additionalProperties": false}`),
		},
		{
			Name:  toolCreateSilence,
			Title: "Create a silence",
			Description: "Silences the Alertmanager alerts that match all the matchers, for a duration such as \"2h\" or " +
				"\"3d\" (30 days at most), with a comment saying why.",
			Kind: model.AIToolKindExternalWrite,
			InputSchema: json.RawMessage(`{"type": "object", "properties": {` + instanceProperty + `,
				"matchers": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "object", "properties": {
					"name": {"type": "string", "description": "A label name, such as alertname or instance."},
					"value": {"type": "string"},
					"is_regex": {"type": "boolean", "description": "The value is a regular expression (default false)."},
					"is_equal": {"type": "boolean", "description": "False for a negative matcher (!= or !~). Default true."}
				}, "required": ["name", "value"], "additionalProperties": false}},
				"duration": {"type": "string", "description": "How long the silence lasts: 30m, 2h, 1d, 1w."},
				"comment": {"type": "string", "description": "Why the alerts are silenced."}
			}, "required": ["matchers", "duration", "comment"], "additionalProperties": false}`),
		},
		{
			Name:        toolExpireSilence,
			Title:       "Expire a silence",
			Description: "Ends an Alertmanager silence now, by its ID (from list_silences).",
			Kind:        model.AIToolKindExternalWrite,
			InputSchema: json.RawMessage(`{"type": "object", "properties": {` + instanceProperty + `,
				"id": {"type": "string", "description": "The silence's ID."}
			}, "required": ["id"], "additionalProperties": false}`),
		},
	}
}

// stringList takes a list of strings, or one string.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one != "" {
			*l = stringList{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("expected a list of strings")
	}
	*l = many
	return nil
}

func checkFilters(filter stringList) error {
	if len(filter) > maxToolFilters {
		return fmt.Errorf("at most %d filters", maxToolFilters)
	}
	for _, f := range filter {
		if f == "" || len(f) > maxFilterLength || strings.ContainsAny(f, "\r\n") {
			return errors.New("a filter isn't a label matcher")
		}
	}
	return nil
}

type listAlertsArgs struct {
	Instance  string     `json:"alertmanager"`
	Receiver  string     `json:"receiver"`
	Target    string     `json:"target"`
	Filter    stringList `json:"filter"`
	Active    *bool      `json:"active"`
	Silenced  *bool      `json:"silenced"`
	Inhibited *bool      `json:"inhibited"`
}

type listSilencesArgs struct {
	Instance string     `json:"alertmanager"`
	Filter   stringList `json:"filter"`
}

type toolMatcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex"`
	IsEqual *bool  `json:"is_equal"`
}

type createSilenceArgs struct {
	Instance string        `json:"alertmanager"`
	Matchers []toolMatcher `json:"matchers"`
	Duration string        `json:"duration"`
	Comment  string        `json:"comment"`
}

type expireSilenceArgs struct {
	Instance string `json:"alertmanager"`
	ID       string `json:"id"`
}

// The results: compact, for the assistant's cards. list_alerts and list_silences give message
// attachments, in the same format the app's own alert posts use (render.go), plus a plain-text
// summary (display.go's toolDisplayResult). The action tools below keep their own plain
// confirmation shape: they report what was done, not something to show as a card.

type silenceResult struct {
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	Instance string `json:"alertmanager"`
	ID       string `json:"id"`
	Matchers string `json:"matchers,omitempty"`
	EndsAt   string `json:"ends_at,omitempty"`
}

// ExecuteAITool runs one of the app's tools for an agent, for the person in the call.
func (p *Plugin) ExecuteAITool(_ *plugin.Context, call *model.AIToolExecution) *model.AIToolResult {
	s := p.getSettings()
	if call == nil || !model.IsValidId(call.UserId) {
		return &model.AIToolResult{Error: "the tool needs a person to run for"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()

	var result any
	var err error
	arguments := call.Arguments
	if len(arguments) == 0 || string(arguments) == "null" {
		arguments = json.RawMessage("{}")
	}
	decode := func(out any) error {
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(out); decodeErr != nil {
			return errors.New("the arguments aren't valid: " + decodeErr.Error())
		}
		return nil
	}
	switch call.Tool {
	case toolListAlerts:
		var args listAlertsArgs
		if err = decode(&args); err == nil {
			result, err = p.toolListAlerts(ctx, s, call.UserId, &args)
		}
	case toolListSilences:
		var args listSilencesArgs
		if err = decode(&args); err == nil {
			result, err = p.toolListSilences(ctx, s, call.UserId, &args)
		}
	case toolCreateSilence:
		var args createSilenceArgs
		if err = decode(&args); err == nil {
			result, err = p.toolCreateSilence(ctx, s, call.UserId, &args)
		}
	case toolExpireSilence:
		var args expireSilenceArgs
		if err = decode(&args); err == nil {
			result, err = p.toolExpireSilence(ctx, s, call.UserId, &args)
		}
	default:
		err = errors.New("unknown tool")
	}
	if err != nil {
		return &model.AIToolResult{Error: s.redact(truncateRunes(err.Error(), 500))}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return &model.AIToolResult{Error: "the result couldn't be encoded"}
	}
	return &model.AIToolResult{Text: s.redact(string(data))}
}

// routedChannels gives the channels the instance's routes name, by receiver, that exist.
func (p *Plugin) routedChannels(inst *instance) map[string][]*model.Channel {
	out := map[string][]*model.Channel{}
	for _, route := range inst.routes {
		if channel, err := p.routeChannel(route); err == nil {
			out[route.Receiver] = append(out[route.Receiver], channel)
		}
	}
	return out
}

// visibleReceivers gives the receivers of an instance routed to a channel the person can read.
func (p *Plugin) visibleReceivers(inst *instance, userID string) map[string]bool {
	out := map[string]bool{}
	for receiver, channels := range p.routedChannels(inst) {
		for _, channel := range channels {
			if p.canReadChannel(userID, channel) {
				out[receiver] = true
				break
			}
		}
	}
	return out
}

// checkInstanceSilenceRight checks the silence right in every channel the instance is routed to: a silence made with
// a tool can match any alert of the instance.
func (p *Plugin) checkInstanceSilenceRight(s *settings, inst *instance, userID string) error {
	channels := p.routedChannels(inst)
	if len(channels) == 0 {
		return errNoInstanceSilence
	}
	for _, list := range channels {
		for _, channel := range list {
			if err := p.checkSilenceRight(s, userID, channel.Id); err != nil {
				return errNoInstanceSilence
			}
		}
	}
	return nil
}

// readableInstances gives the instances a read tool looks at, each with the receivers the person can see. An instance
// they can't see counts as unknown.
func (p *Plugin) readableInstances(s *settings, userID, name string) ([]*instance, map[string]map[string]bool, error) {
	receivers := map[string]map[string]bool{}
	var out []*instance
	for _, n := range s.names {
		if name != "" && n != name {
			continue
		}
		inst := s.instances[n]
		visible := p.visibleReceivers(inst, userID)
		if len(visible) == 0 {
			continue
		}
		out = append(out, inst)
		receivers[n] = visible
	}
	if len(out) == 0 {
		return nil, nil, errUnknownInstance
	}
	return out, receivers, nil
}

// actionInstance gives the instance an action tool works on: the one named, or the only one the person can see.
func (p *Plugin) actionInstance(s *settings, userID, name string) (*instance, error) {
	if name != "" {
		inst := s.instances[name]
		if inst == nil || len(p.visibleReceivers(inst, userID)) == 0 {
			return nil, errUnknownInstance
		}
		return inst, nil
	}
	instances, _, err := p.readableInstances(s, userID, "")
	if err != nil {
		return nil, err
	}
	if len(instances) > 1 {
		names := make([]string, 0, len(instances))
		for _, inst := range instances {
			names = append(names, inst.name)
		}
		return nil, fmt.Errorf("%w: %s", errNameInstance, strings.Join(names, ", "))
	}
	return instances[0], nil
}

func (p *Plugin) toolListAlerts(ctx context.Context, s *settings, userID string, args *listAlertsArgs) (*toolDisplayResult, error) {
	if err := checkFilters(args.Filter); err != nil {
		return nil, err
	}
	args.Target = strings.TrimSpace(args.Target)
	if len(args.Target) > maxFilterLength || strings.ContainsAny(args.Target, "\r\n") {
		return nil, errBadTarget
	}
	instances, receivers, err := p.readableInstances(s, userID, args.Instance)
	if err != nil {
		return nil, err
	}
	if args.Receiver != "" {
		var kept []*instance
		for _, inst := range instances {
			if receivers[inst.name][args.Receiver] {
				kept = append(kept, inst)
			}
		}
		if len(kept) == 0 {
			return nil, errUnknownReceiver
		}
		instances = kept
	}

	now := p.now()
	var attachments []*model.MessageAttachment
	total, firing, silenced, inhibited := 0, 0, 0, 0
	severities := map[string]int{}
	for _, inst := range instances {
		alerts, err := inst.alerts(ctx, alertQuery{
			Filter: args.Filter, Receiver: args.Receiver, Active: args.Active, Silenced: args.Silenced, Inhibited: args.Inhibited,
		})
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", inst.name, err)
		}
		for _, a := range alerts {
			visible := false
			for _, r := range a.Receivers {
				if receivers[inst.name][r.Name] && (args.Receiver == "" || r.Name == args.Receiver) {
					visible = true
					break
				}
			}
			if !visible || (!s.postSeverityNone && strings.EqualFold(a.Labels["severity"], "none")) ||
				(args.Target != "" && !aboutTarget(a.Labels, args.Target)) {
				continue
			}
			state := alertDisplayState(a, now)
			switch state {
			case alertStateSilenced:
				silenced++
			case alertStateInhibited:
				inhibited++
			default:
				firing++
				if sev := a.Labels["severity"]; sev != "" {
					severities[strings.ToLower(sev)]++
				}
			}
			total++
			if len(attachments) < maxShownAlertAttachments {
				instanceName := ""
				if len(instances) > 1 {
					instanceName = inst.name
				}
				attachments = append(attachments, alertAttachment(a, state, instanceName))
			}
		}
	}

	scopeName := ""
	title := "Alerts"
	if len(instances) == 1 {
		scopeName = instances[0].name
		title = "Alerts of " + scopeName
	}
	if total == 0 {
		text := noAlertsText(scopeName)
		return &toolDisplayResult{Attachments: []*model.MessageAttachment{noItemsAttachment(text)}, Summary: text}, nil
	}
	if more := total - len(attachments); more > 0 {
		attachments = append(attachments, moreAttachment(more, "alerts"))
	}
	return &toolDisplayResult{Attachments: attachments, Summary: title + ": " + alertsSummary(firing, silenced, inhibited, severities)}, nil
}

// aboutTarget tells whether an alert is about a host or target: its instance label, with or without the port, or
// else its job, as alertTarget shows it.
func aboutTarget(labels map[string]string, target string) bool {
	instance := labels["instance"]
	if instance == "" {
		return strings.EqualFold(labels["job"], target)
	}
	if strings.EqualFold(instance, target) {
		return true
	}
	if host, _, err := net.SplitHostPort(instance); err == nil {
		return strings.EqualFold(host, target)
	}
	return false
}

func alertsSummary(firing, silenced, inhibited int, severities map[string]int) string {
	if firing+silenced+inhibited == 0 {
		return "No alerts."
	}
	parts := []string{fmt.Sprintf("%d firing", firing)}
	if len(severities) > 0 {
		var bySeverity []string
		for _, sev := range slices.Sorted(maps.Keys(severities)) {
			bySeverity = append(bySeverity, fmt.Sprintf("%d %s", severities[sev], sev))
		}
		parts[0] += " (" + strings.Join(bySeverity, ", ") + ")"
	}
	if silenced > 0 {
		parts = append(parts, fmt.Sprintf("%d silenced", silenced))
	}
	if inhibited > 0 {
		parts = append(parts, fmt.Sprintf("%d inhibited", inhibited))
	}
	return strings.Join(parts, ", ") + "."
}

func matchersText(matchers []amMatcher) string {
	parts := make([]string, 0, len(matchers))
	for _, m := range matchers {
		parts = append(parts, m.String())
	}
	return strings.Join(parts, ", ")
}

func (p *Plugin) toolListSilences(ctx context.Context, s *settings, userID string, args *listSilencesArgs) (*toolDisplayResult, error) {
	if err := checkFilters(args.Filter); err != nil {
		return nil, err
	}
	instances, _, err := p.readableInstances(s, userID, args.Instance)
	if err != nil {
		return nil, err
	}
	type row struct{ matchers, until, by, comment string }
	var rows []row
	active, pending, total := 0, 0, 0
	for _, inst := range instances {
		silences, err := inst.silences(ctx, args.Filter)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", inst.name, err)
		}
		slices.SortFunc(silences, func(a, b amSilence) int { return a.EndsAt.Compare(b.EndsAt) })
		for _, sil := range silences {
			switch sil.Status.State {
			case "active":
				active++
			case "pending":
				pending++
			default:
				continue
			}
			total++
			if len(rows) == maxToolSilences {
				continue
			}
			until := formatTime(sil.EndsAt)
			if sil.Status.State == "pending" {
				until = "from " + formatTime(sil.StartsAt) + " until " + until
			}
			by := truncateRunes(sil.CreatedBy, 100)
			if len(instances) > 1 {
				by = strings.TrimSpace(by + " (" + inst.name + ")")
			}
			rows = append(rows, row{
				matchers: truncateRunes(matchersText(sil.Matchers), maxToolTextRunes),
				until:    until,
				by:       by,
				comment:  truncateRunes(sil.Comment, 200),
			})
		}
	}

	title := "Silences"
	if len(instances) == 1 {
		title = "Silences of " + instances[0].name
	}
	var countSummary string
	switch {
	case active+pending == 0:
		countSummary = "No active silences."
	case pending == 0:
		countSummary = fmt.Sprintf("%d active.", active)
	default:
		countSummary = fmt.Sprintf("%d active, %d pending.", active, pending)
	}

	summary := title + ": " + countSummary
	if len(rows) == 0 {
		att := noItemsAttachment(countSummary)
		att.Title = title
		return &toolDisplayResult{Attachments: []*model.MessageAttachment{att}, Summary: summary}, nil
	}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{r.matchers, r.until, r.by, r.comment}
	}
	text := markdownTable([]string{"Matchers", "Until", "By", "Comment"}, tableRows)
	if more := total - len(rows); more > 0 {
		text += fmt.Sprintf("\n\n_+%d more not shown._", more)
	}
	attachment := &model.MessageAttachment{
		Fallback: summary,
		Title:    title,
		Text:     text,
		Footer:   "Alertmanager",
	}
	return &toolDisplayResult{Attachments: []*model.MessageAttachment{attachment}, Summary: summary}, nil
}

// parseSilenceDuration reads a duration: Go's (90m, 2h30m) with days (d) and weeks (w) too.
func parseSilenceDuration(text string) (time.Duration, error) {
	text = strings.TrimSpace(strings.ToLower(text))
	if text == "" {
		return 0, errors.New("the duration is missing")
	}
	for unit, size := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if number, ok := strings.CutSuffix(text, unit); ok {
			n, err := strconv.ParseFloat(number, 64)
			if err != nil || n <= 0 || n > 60 {
				return 0, errors.New("the duration isn't valid")
			}
			return time.Duration(n * float64(size)), nil
		}
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, errors.New("the duration isn't valid: use 30m, 2h, 1d or 1w")
	}
	return d, nil
}

// checkMatchers checks the matchers a model gave and makes them Alertmanager's.
func checkMatchers(in []toolMatcher) ([]amMatcher, error) {
	if len(in) == 0 || len(in) > maxToolMatchers {
		return nil, fmt.Errorf("give 1 to %d matchers", maxToolMatchers)
	}
	out := make([]amMatcher, 0, len(in))
	matchesAll := true
	for _, m := range in {
		if !labelNamePattern.MatchString(m.Name) {
			return nil, errors.New("a matcher's name isn't a label name")
		}
		if len(m.Value) > maxMatcherValue {
			return nil, errors.New("a matcher's value is too long")
		}
		equal := m.IsEqual == nil || *m.IsEqual
		if m.IsRegex {
			re, err := regexp.Compile("^(?:" + m.Value + ")$")
			if err != nil {
				return nil, errors.New("a matcher's regular expression isn't valid")
			}
			if !equal || !re.MatchString("") {
				matchesAll = false
			}
		} else if !equal || m.Value != "" {
			matchesAll = false
		}
		out = append(out, amMatcher{Name: m.Name, Value: m.Value, IsRegex: m.IsRegex, IsEqual: &equal})
	}
	if matchesAll {
		return nil, errors.New("at least one matcher must not match an empty value")
	}
	return out, nil
}

func (p *Plugin) toolCreateSilence(ctx context.Context, s *settings, userID string, args *createSilenceArgs) (*silenceResult, error) {
	inst, err := p.actionInstance(s, userID, args.Instance)
	if err != nil {
		return nil, err
	}
	if err = p.checkInstanceSilenceRight(s, inst, userID); err != nil {
		return nil, err
	}
	matchers, err := checkMatchers(args.Matchers)
	if err != nil {
		return nil, err
	}
	duration, err := parseSilenceDuration(args.Duration)
	if err != nil {
		return nil, err
	}
	if err = checkSilenceLength(duration); err != nil {
		return nil, err
	}
	comment := strings.TrimSpace(args.Comment)
	if comment == "" {
		return nil, errors.New("a silence needs a comment")
	}
	user, appErr := p.API.GetUser(userID)
	if appErr != nil || user == nil {
		return nil, errNoInstanceSilence
	}
	now := p.now()
	until := now.Add(duration).UTC()
	id, err := inst.createSilence(ctx, &amPostableSilence{
		Matchers:  matchers,
		StartsAt:  now.UTC(),
		EndsAt:    until,
		CreatedBy: "@" + user.Username,
		Comment:   truncateRunes(comment, maxCommentRunes),
	})
	if err != nil {
		return nil, err
	}
	if err := p.store.saveSilenceIndex(inst.name, id, &silenceIndex{}, until, now); err != nil {
		p.API.LogWarn("Alertmanager: a silence couldn't be recorded", "instance", inst.name, "error", err.Error())
	}
	text := matchersText(matchers)
	return &silenceResult{
		Title:    "Silence created",
		Summary:  fmt.Sprintf("Silenced %s until %s.", truncateRunes(text, 200), formatTime(until)),
		Instance: inst.name,
		ID:       id,
		Matchers: truncateRunes(text, maxToolTextRunes),
		EndsAt:   formatTime(until),
	}, nil
}

func (p *Plugin) toolExpireSilence(ctx context.Context, s *settings, userID string, args *expireSilenceArgs) (*silenceResult, error) {
	id := strings.TrimSpace(args.ID)
	if !silenceIDPattern.MatchString(id) {
		return nil, errNoSuchSilence
	}
	inst, err := p.actionInstance(s, userID, args.Instance)
	if err != nil {
		return nil, err
	}
	idx, err := p.store.getSilenceIndex(inst.name, id)
	if err != nil {
		return nil, err
	}
	if idx != nil && idx.ChannelID != "" {
		// A silence set from an alert post: the right in that post's channel is enough.
		if err = p.checkSilenceRight(s, userID, idx.ChannelID); err != nil {
			return nil, err
		}
	} else if err = p.checkInstanceSilenceRight(s, inst, userID); err != nil {
		return nil, err
	}
	user, appErr := p.API.GetUser(userID)
	if appErr != nil || user == nil {
		return nil, errNoInstanceSilence
	}

	silence, err := inst.silence(ctx, id)
	if isNotFound(err) {
		return nil, errNoSuchSilence
	} else if err != nil {
		return nil, err
	}
	text := matchersText(silence.Matchers)
	if silence.Status.State == "expired" {
		return &silenceResult{Title: "Silence already expired", Summary: "That silence had already ended.", Instance: inst.name, ID: id, Matchers: truncateRunes(text, maxToolTextRunes)}, nil
	}
	if err := inst.expireSilence(ctx, id); err != nil {
		return nil, err
	}
	if idx != nil && idx.GroupKey != "" {
		p.clearGroupSilence(idx.GroupKey, id, user.Username)
	}
	return &silenceResult{
		Title:    "Silence expired",
		Summary:  fmt.Sprintf("Expired the silence of %s.", truncateRunes(text, 200)),
		Instance: inst.name,
		ID:       id,
		Matchers: truncateRunes(text, maxToolTextRunes),
	}, nil
}

// clearGroupSilence takes an expired silence off the post it was set from.
func (p *Plugin) clearGroupSilence(key, silenceID, username string) {
	unlock := p.groupLocks.lock(key)
	defer unlock()
	rec, err := p.store.getGroup(key)
	if err != nil || rec == nil || rec.Silence == nil || rec.Silence.ID != silenceID {
		return
	}
	rec.Silence = nil
	if err := p.store.saveGroup(key, rec); err != nil {
		return
	}
	p.refreshPost(rec, p.now())
	p.reply(rec, fmt.Sprintf("Silence expired by @%s.", username))
}
