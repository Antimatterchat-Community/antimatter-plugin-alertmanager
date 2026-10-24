// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The Alertmanager v2 API, as far as the app uses it.

const maxAlertmanagerResponse = 8 << 20

var silenceIDPattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

// amMatcher is a matcher of a silence.
type amMatcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual *bool  `json:"isEqual,omitempty"`
}

// equal tells whether the matcher is = or =~ (not != or !~).
func (m amMatcher) equal() bool {
	return m.IsEqual == nil || *m.IsEqual
}

func (m amMatcher) String() string {
	op := "="
	switch {
	case m.IsRegex && m.equal():
		op = "=~"
	case m.IsRegex:
		op = "!~"
	case !m.equal():
		op = "!="
	}
	return m.Name + op + strconv.Quote(m.Value)
}

type amSilenceStatus struct {
	State string `json:"state"`
}

// amSilence is a silence as Alertmanager gives it.
type amSilence struct {
	ID        string          `json:"id"`
	Status    amSilenceStatus `json:"status"`
	Matchers  []amMatcher     `json:"matchers"`
	StartsAt  time.Time       `json:"startsAt"`
	EndsAt    time.Time       `json:"endsAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
	CreatedBy string          `json:"createdBy"`
	Comment   string          `json:"comment"`
}

// amPostableSilence is a silence to create (or, with an ID, to replace).
type amPostableSilence struct {
	ID        string      `json:"id,omitempty"`
	Matchers  []amMatcher `json:"matchers"`
	StartsAt  time.Time   `json:"startsAt"`
	EndsAt    time.Time   `json:"endsAt"`
	CreatedBy string      `json:"createdBy"`
	Comment   string      `json:"comment"`
}

type amReceiver struct {
	Name string `json:"name"`
}

type amAlertStatus struct {
	State       string   `json:"state"`
	SilencedBy  []string `json:"silencedBy"`
	InhibitedBy []string `json:"inhibitedBy"`
}

// amAlert is an alert as Alertmanager's API gives it.
type amAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
	Receivers    []amReceiver      `json:"receivers"`
	Status       amAlertStatus     `json:"status"`
}

// alertQuery is the query of GET /api/v2/alerts.
type alertQuery struct {
	Filter    []string
	Receiver  string
	Active    *bool
	Silenced  *bool
	Inhibited *bool
}

// amError is an answer of Alertmanager that isn't a success.
type amError struct {
	Status  int
	Message string
}

func (e *amError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Alertmanager answered %d", e.Status)
	}
	return fmt.Sprintf("Alertmanager answered %d: %s", e.Status, e.Message)
}

var errAlertmanagerUnreachable = errors.New("couldn't reach Alertmanager")

// do sends a request to the instance's API and decodes its JSON answer into out (when not nil).
func (i *instance) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	target := *i.baseURL
	target.Path = i.baseURL.Path + path
	target.RawQuery = query.Encode()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return errAlertmanagerUnreachable
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if i.authHeader != "" {
		req.Header.Set("Authorization", i.authHeader)
	}
	resp, err := i.client.Do(req)
	if err != nil {
		// The error names the address, never the credentials (they're in a header); it isn't passed on anyway.
		if errors.Is(err, errForbiddenAddress) {
			return errForbiddenAddress
		}
		return errAlertmanagerUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAlertmanagerResponse+1))
	if err != nil {
		return errAlertmanagerUnreachable
	}
	if len(data) > maxAlertmanagerResponse {
		return errors.New("the answer of Alertmanager is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &amError{Status: resp.StatusCode, Message: shortErrorMessage(data)}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("the answer of Alertmanager isn't what the app expected")
	}
	return nil
}

// shortErrorMessage gives the first line of an error answer, short, as plain text.
func shortErrorMessage(data []byte) string {
	text := string(data)
	var structured struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &structured) == nil && structured.Message != "" {
		text = structured.Message
	} else if s := ""; json.Unmarshal(data, &s) == nil && s != "" {
		text = s
	}
	text, _, _ = strings.Cut(strings.TrimSpace(text), "\n")
	if !utf8.ValidString(text) || strings.ContainsAny(text, "<>") {
		return ""
	}
	return truncateRunes(text, 200)
}

func boolParam(values url.Values, name string, value *bool) {
	if value != nil {
		values.Set(name, strconv.FormatBool(*value))
	}
}

// alerts lists alerts (GET /api/v2/alerts).
func (i *instance) alerts(ctx context.Context, q alertQuery) ([]amAlert, error) {
	values := url.Values{}
	for _, f := range q.Filter {
		values.Add("filter", f)
	}
	if q.Receiver != "" {
		values.Set("receiver", "^(?:"+regexp.QuoteMeta(q.Receiver)+")$")
	}
	boolParam(values, "active", q.Active)
	boolParam(values, "silenced", q.Silenced)
	boolParam(values, "inhibited", q.Inhibited)
	var out []amAlert
	err := i.do(ctx, http.MethodGet, "/api/v2/alerts", values, nil, &out)
	return out, err
}

// silences lists silences (GET /api/v2/silences).
func (i *instance) silences(ctx context.Context, filter []string) ([]amSilence, error) {
	values := url.Values{}
	for _, f := range filter {
		values.Add("filter", f)
	}
	var out []amSilence
	err := i.do(ctx, http.MethodGet, "/api/v2/silences", values, nil, &out)
	return out, err
}

// silence gets one silence (GET /api/v2/silence/{id}).
func (i *instance) silence(ctx context.Context, id string) (*amSilence, error) {
	if !silenceIDPattern.MatchString(id) {
		return nil, errors.New("that isn't a silence ID")
	}
	var out amSilence
	if err := i.do(ctx, http.MethodGet, "/api/v2/silence/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// createSilence creates a silence, or replaces the one with its ID (POST /api/v2/silences), and gives its ID.
func (i *instance) createSilence(ctx context.Context, s *amPostableSilence) (string, error) {
	var out struct {
		SilenceID string `json:"silenceID"`
	}
	if err := i.do(ctx, http.MethodPost, "/api/v2/silences", nil, s, &out); err != nil {
		return "", err
	}
	if !silenceIDPattern.MatchString(out.SilenceID) {
		return "", errors.New("the answer of Alertmanager has no silence ID")
	}
	return out.SilenceID, nil
}

// expireSilence ends a silence now (DELETE /api/v2/silence/{id}).
func (i *instance) expireSilence(ctx context.Context, id string) error {
	if !silenceIDPattern.MatchString(id) {
		return errors.New("that isn't a silence ID")
	}
	return i.do(ctx, http.MethodDelete, "/api/v2/silence/"+url.PathEscape(id), nil, nil, nil)
}

func truncateRunes(text string, limit int) string {
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	runes := []rune(text)
	return strings.TrimSpace(string(runes[:limit-1])) + "…"
}
