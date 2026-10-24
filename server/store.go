// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// What the app keeps in its KV store:
//   - grp_<key>: a groupRecord, the post of an alert group (an Alertmanager groupKey) in one channel;
//   - post_<post id>: the key of the group the post shows;
//   - sil_<hash of instance and silence ID>: a silenceIndex, where a silence the app created applies.

const (
	groupPrefix   = "grp_"
	postPrefix    = "post_"
	silencePrefix = "sil_"
	// maxStoredAlerts is how many alerts of a group are kept and shown.
	maxStoredAlerts = 20
)

// alertView is an alert of a group as the post shows it.
type alertView struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     time.Time         `json:"starts_at"`
	EndsAt       time.Time         `json:"ends_at"`
	GeneratorURL string            `json:"generator_url,omitempty"`
}

// silenceRecord is a silence set from a post.
type silenceRecord struct {
	ID       string    `json:"id"`
	ByUserID string    `json:"by_user_id"`
	ByName   string    `json:"by_name"`
	Until    time.Time `json:"until"`
	Comment  string    `json:"comment,omitempty"`
}

// groupRecord is the post of an alert group in a channel.
type groupRecord struct {
	Instance     string            `json:"instance"`
	ChannelID    string            `json:"channel_id"`
	GroupKey     string            `json:"group_key"`
	Receiver     string            `json:"receiver"`
	PostID       string            `json:"post_id"`
	Status       string            `json:"status"`
	GroupLabels  map[string]string `json:"group_labels"`
	CommonLabels map[string]string `json:"common_labels"`
	Alerts       []alertView       `json:"alerts"`
	// AlertCount counts every alert of the group, also those not kept.
	AlertCount int            `json:"alert_count"`
	Silence    *silenceRecord `json:"silence,omitempty"`
	UpdatedAt  int64          `json:"updated_at"`
}

// activeSilence gives the record's silence while it lasts.
func (r *groupRecord) activeSilence(now time.Time) *silenceRecord {
	if r.Silence == nil || !r.Silence.Until.After(now) {
		return nil
	}
	return r.Silence
}

// silenceIndex says where a silence the app created applies: the channel and group of the post it was set from,
// or none for one created with an agent's tool (it then applies to the whole instance).
type silenceIndex struct {
	ChannelID string `json:"channel_id,omitempty"`
	GroupKey  string `json:"group_key,omitempty"`
}

// kvAPI is the part of the plugin API the store uses.
type kvAPI interface {
	KVGet(key string) ([]byte, *model.AppError)
	KVSetWithOptions(key string, value []byte, options model.PluginKVSetOptions) (bool, *model.AppError)
}

// Store keeps the app's records.
type Store struct {
	api kvAPI
}

func hashKey(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:40]
}

// groupKeyOf names the record of a group in a channel.
func groupKeyOf(instanceName, channelID, groupKey string) string {
	return hashKey(instanceName, channelID, groupKey)
}

func (s *Store) getJSON(key string, out any) (bool, error) {
	data, appErr := s.api.KVGet(key)
	if appErr != nil {
		return false, appErr
	}
	if data == nil {
		return false, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) setJSON(key string, value any, expireSeconds int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	ok, appErr := s.api.KVSetWithOptions(key, data, model.PluginKVSetOptions{ExpireInSeconds: expireSeconds})
	if appErr != nil {
		return appErr
	}
	if !ok {
		return errors.New("the value wasn't saved")
	}
	return nil
}

// recordTTL keeps a group's record for a while after its last update: Alertmanager repeats firing alerts (every
// repeat_interval, 4 hours by default), so an alert that still fires keeps its record.
const recordTTL = 30 * 24 * 60 * 60

func (s *Store) getGroup(key string) (*groupRecord, error) {
	var rec groupRecord
	found, err := s.getJSON(groupPrefix+key, &rec)
	if err != nil || !found {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) saveGroup(key string, rec *groupRecord) error {
	if err := s.setJSON(groupPrefix+key, rec, recordTTL); err != nil {
		return err
	}
	return s.setJSON(postPrefix+rec.PostID, key, recordTTL)
}

// groupForPost gives the group a post shows, and its key.
func (s *Store) groupForPost(postID string) (*groupRecord, string, error) {
	var key string
	found, err := s.getJSON(postPrefix+postID, &key)
	if err != nil || !found {
		return nil, "", err
	}
	rec, err := s.getGroup(key)
	if err != nil || rec == nil || rec.PostID != postID {
		return nil, "", err
	}
	return rec, key, nil
}

func silenceIndexKey(instanceName, silenceID string) string {
	return silencePrefix + hashKey(instanceName, silenceID)
}

func (s *Store) getSilenceIndex(instanceName, silenceID string) (*silenceIndex, error) {
	var idx silenceIndex
	found, err := s.getJSON(silenceIndexKey(instanceName, silenceID), &idx)
	if err != nil || !found {
		return nil, err
	}
	return &idx, nil
}

func (s *Store) saveSilenceIndex(instanceName, silenceID string, idx *silenceIndex, until time.Time, now time.Time) error {
	ttl := int64(until.Sub(now).Seconds()) + 24*60*60
	return s.setJSON(silenceIndexKey(instanceName, silenceID), idx, ttl)
}

// keyedMutex serialises the work on each group, so that two webhooks of one group don't make two posts.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	sync.Mutex
	users int
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.users++
	k.mu.Unlock()

	l.Lock()
	return func() {
		l.Unlock()
		k.mu.Lock()
		l.users--
		if l.users == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
