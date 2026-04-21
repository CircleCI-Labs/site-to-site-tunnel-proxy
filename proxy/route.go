package proxy

import (
	"fmt"
	"net"
	"strings"
)

// Route describes how to reach one upstream via the proxy.
type Route struct {
	TargetAddr   string // dial address, e.g. "domain.example.com:443"
	TargetDomain string // TLS SNI / display name, e.g. "domain.example.com"
	UseTLS       bool   // true → outer TLS + mTLS client cert (opt-in via tls:// prefix); false → plain TCP
}

// ParseTunnelFlag parses "HOST[:PORT]=DOMAIN[:PORT]" into a route map entry.
//
// LHS port defaults to 443 if absent.
// RHS port defaults to 443 if absent. Prefix the RHS with "tls://" to wrap
// the connection in TLS (e.g. "host=tls://domain:443"). Without the prefix,
// connections use plain TCP; application-layer encryption (SSH, HTTPS) is
// handled end-to-end without an outer TLS wrapper.
func ParseTunnelFlag(s string) (listenKey string, route Route, err error) {
	lhs, rhs, ok := strings.Cut(s, "=")
	if !ok {
		return "", Route{}, fmt.Errorf("missing '=': expected HOST[:PORT]=DOMAIN[:PORT], got %q", s)
	}
	if lhs == "" || rhs == "" {
		return "", Route{}, fmt.Errorf("empty LHS or RHS in %q", s)
	}

	// LHS: HOST or HOST:PORT
	listenHost, listenPort := lhs, "443"
	if h, p, e := net.SplitHostPort(lhs); e == nil {
		listenHost, listenPort = h, p
	}
	listenKey = net.JoinHostPort(listenHost, listenPort)

	// RHS: [tls://]DOMAIN[:PORT]
	useTLS := strings.HasPrefix(rhs, "tls://")
	rhs = strings.TrimPrefix(rhs, "tls://")

	targetHost, targetPort := rhs, "443"
	if h, p, e := net.SplitHostPort(rhs); e == nil {
		targetHost, targetPort = h, p
	}

	route = Route{
		TargetAddr:   net.JoinHostPort(targetHost, targetPort),
		TargetDomain: targetHost,
		UseTLS:       useTLS,
	}
	return listenKey, route, nil
}

// ParseTunnelFlags parses multiple tunnel flag values into a route map.
func ParseTunnelFlags(flags []string) (map[string]Route, error) {
	routes := make(map[string]Route, len(flags))
	for _, f := range flags {
		key, route, err := ParseTunnelFlag(f)
		if err != nil {
			return nil, fmt.Errorf("--tunnel %s: %w", f, err)
		}
		if _, dup := routes[key]; dup {
			return nil, fmt.Errorf("--tunnel: duplicate route for %s", key)
		}
		routes[key] = route
	}
	return routes, nil
}
