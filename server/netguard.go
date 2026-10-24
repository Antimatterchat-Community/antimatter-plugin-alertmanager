// Copyright (c) 2026-present Antimatter contributors.
// See LICENSE for license information.

package main

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const (
	dialTimeout           = 10 * time.Second
	keepAlive             = 30 * time.Second
	alertmanagerTimeout   = 20 * time.Second
	responseHeaderTimeout = 15 * time.Second
)

var errForbiddenAddress = errors.New("connecting to link-local, metadata or non-unicast addresses isn't allowed")

// metadataPrefixes are cloud metadata and host services outside the link-local ranges: Alibaba Cloud's metadata
// service, AWS's IPv6 metadata service (in the private fc00::/7 range), and Azure's host address (WireServer).
var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("168.63.129.16/32"),
}

var (
	// thisNetwork is 0.0.0.0/8, which some systems route to the host itself.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	broadcast   = netip.MustParseAddr("255.255.255.255")
	// nat64 and sixToFour embed an IPv4 address, which is checked too.
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// isForbiddenIP tells whether an address must not be dialled: link-local (where the cloud metadata services live),
// metadata services, multicast, unspecified and broadcast addresses. Private and loopback addresses are allowed:
// Alertmanager usually runs on an internal network, and only system admins set its address.
func isForbiddenIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip == broadcast || thisNetwork.Contains(ip) {
		return true
	}
	for _, prefix := range metadataPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	if ip.Is6() {
		bytes := ip.As16()
		if nat64.Contains(ip) {
			return isForbiddenIP(netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]}))
		}
		if sixToFour.Contains(ip) {
			return isForbiddenIP(netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]}))
		}
	}
	return false
}

// newDialer gives the dialer of the connections to Alertmanager. The check runs on the address of each connection,
// after name resolution, so a name that resolves to a forbidden address is refused too.
func newDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil || isForbiddenIP(addrPort.Addr()) {
				return errForbiddenAddress
			}
			return nil
		},
	}
}

// newAlertmanagerHTTPClient gives the client of an Alertmanager instance: guarded dialer, no proxy from the
// environment (it would hide the address dialled), and no redirects (they'd carry the request elsewhere).
func newAlertmanagerHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           newDialer().DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   alertmanagerTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
