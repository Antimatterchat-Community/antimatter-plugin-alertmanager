// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"errors"

	"github.com/mattermost/mattermost/server/public/model"
)

var (
	errNotInChannel = errors.New("you're not a member of the channel the alert is posted in")
	errNoSilence    = errors.New("you may not silence alerts in this channel")
)

// checkSilenceRight tells whether a person may silence alerts, and expire silences, in a channel, by the settings:
// they must be a member of the channel and, by default, one of its admins or of its community's (or a system admin);
// or anyone who can post in it; or a system admin only.
func (p *Plugin) checkSilenceRight(s *settings, userID, channelID string) error {
	if userID == "" || channelID == "" {
		return errNoSilence
	}
	channel, appErr := p.API.GetChannel(channelID)
	if appErr != nil || channel == nil || channel.DeleteAt != 0 {
		return errNotInChannel
	}
	member, appErr := p.API.GetChannelMember(channelID, userID)
	if appErr != nil || member == nil {
		return errNotInChannel
	}
	isSystemAdmin := p.API.HasPermissionTo(userID, model.PermissionManageSystem)

	switch s.silencePermission {
	case silenceBySystemAdmins:
		if isSystemAdmin {
			return nil
		}
	case silenceByChannelPosters:
		if p.API.HasPermissionToChannel(userID, channelID, model.PermissionCreatePost) {
			return nil
		}
	default:
		if isSystemAdmin || member.SchemeAdmin {
			return nil
		}
		if channel.TeamId != "" {
			if teamMember, appErr := p.API.GetTeamMember(channel.TeamId, userID); appErr == nil && teamMember != nil &&
				teamMember.DeleteAt == 0 && teamMember.SchemeAdmin {
				return nil
			}
		}
	}
	return errNoSilence
}

// canReadChannel tells whether a person may read a channel.
func (p *Plugin) canReadChannel(userID string, channel *model.Channel) bool {
	return userID != "" && channel != nil && channel.DeleteAt == 0 &&
		p.API.HasPermissionToChannel(userID, channel.Id, model.PermissionReadChannelContent)
}
