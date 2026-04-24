package proxy

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// wildcardPrefix is the only supported wildcard form on the LHS of a tunnel
// flag: a leading "*." followed by at least one domain label. Any subdomain
// of the following suffix matches, at any depth.
const wildcardPrefix = "*."

// Route describes how to reach one upstream via the proxy.
type Route struct {
	TargetAddr   string // dial address, e.g. "domain.example.com:443"
	TargetDomain string // TLS SNI / display name, e.g. "domain.example.com"
	UseTLS       bool   // true → outer TLS + mTLS client cert (opt-in via tls:// prefix); false → plain TCP
}

// Entry is a parsed --tunnel flag, either an exact or a wildcard route.
//
// For exact entries (Wildcard=false) Key holds "host:port". For wildcard
// entries (Wildcard=true) Suffix holds the match suffix with a leading
// dot (e.g. ".acmecorp.dev") and Port holds the LHS port.
type Entry struct {
	Wildcard bool
	Key      string
	Suffix   string
	Port     string
	Route    Route
}

// WildcardEntry is a read-only view of a wildcard route, useful for logging.
type WildcardEntry struct {
	Pattern string // original, e.g. "*.acmecorp.dev"
	Port    string
	Route   Route
}

// RouteTable holds exact and wildcard routes and answers Lookup.
//
// Exact matches always take precedence over wildcard matches. Among wildcard
// entries, the longest matching suffix wins (stable within ties).
type RouteTable struct {
	exact    map[string]Route
	wildcard []wildcardEntry
}

type wildcardEntry struct {
	suffix  string // ".acmecorp.dev"
	port    string
	route   Route
	pattern string // original, e.g. "*.acmecorp.dev"
}

// NewRouteTable returns an empty RouteTable.
func NewRouteTable() *RouteTable {
	return &RouteTable{exact: map[string]Route{}}
}

// Lookup resolves a host:port to a Route. Host is case-folded before matching.
//
// Precedence: exact entries are consulted first; if no exact entry matches,
// wildcard entries are scanned longest-suffix-first and the port must match.
func (t *RouteTable) Lookup(host, port string) (Route, bool) {
	if t == nil {
		return Route{}, false
	}
	host = strings.ToLower(host)
	if r, ok := t.exact[net.JoinHostPort(host, port)]; ok {
		return r, true
	}
	for _, w := range t.wildcard {
		if w.port != port {
			continue
		}
		if strings.HasSuffix(host, w.suffix) && len(host) > len(w.suffix) {
			return w.route, true
		}
	}
	return Route{}, false
}

// Len returns the total number of routes.
func (t *RouteTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.exact) + len(t.wildcard)
}

// Exact returns the exact-match routes as a new map. Safe to iterate.
func (t *RouteTable) Exact() map[string]Route {
	if t == nil {
		return nil
	}
	out := make(map[string]Route, len(t.exact))
	for k, v := range t.exact {
		out[k] = v
	}
	return out
}

// Wildcards returns the wildcard entries in deterministic order (longest
// suffix first). Safe to iterate.
func (t *RouteTable) Wildcards() []WildcardEntry {
	if t == nil {
		return nil
	}
	out := make([]WildcardEntry, len(t.wildcard))
	for i, w := range t.wildcard {
		out[i] = WildcardEntry{Pattern: w.pattern, Port: w.port, Route: w.route}
	}
	return out
}

// addExact inserts an exact route. Returns an error on duplicate key.
func (t *RouteTable) addExact(key string, r Route) error {
	if _, dup := t.exact[key]; dup {
		return fmt.Errorf("duplicate route for %s", key)
	}
	t.exact[key] = r
	return nil
}

// addWildcard inserts a wildcard route. Returns an error on duplicate
// (suffix, port) pair.
func (t *RouteTable) addWildcard(suffix, port string, r Route, pattern string) error {
	for _, w := range t.wildcard {
		if w.suffix == suffix && w.port == port {
			return fmt.Errorf("duplicate wildcard route for %s:%s", pattern, port)
		}
	}
	t.wildcard = append(t.wildcard, wildcardEntry{
		suffix:  suffix,
		port:    port,
		route:   r,
		pattern: pattern,
	})
	return nil
}

// ParseTunnelFlag parses "HOST[:PORT]=DOMAIN[:PORT]" into an Entry.
//
// LHS port defaults to 443 if absent.
//
// A leading "*." on the LHS marks a wildcard entry. The wildcard matches any
// subdomain of the following suffix at any depth (e.g. "*.acmecorp.dev"
// matches both "foo.acmecorp.dev" and "a.b.acmecorp.dev" but not the bare
// apex "acmecorp.dev"). Only a single leading "*." is supported; "*" may not
// appear elsewhere on the LHS, and may not appear on the RHS.
//
// RHS port defaults to 443 if absent. Prefix the RHS with "tls://" to wrap
// the connection in TLS (e.g. "host=tls://domain:443"). Without the prefix,
// connections use plain TCP; application-layer encryption (SSH, HTTPS) is
// handled end-to-end without an outer TLS wrapper.
func ParseTunnelFlag(s string) (Entry, error) {
	lhs, rhs, ok := strings.Cut(s, "=")
	if !ok {
		return Entry{}, fmt.Errorf("missing '=': expected HOST[:PORT]=DOMAIN[:PORT], got %q", s)
	}
	if lhs == "" || rhs == "" {
		return Entry{}, fmt.Errorf("empty LHS or RHS in %q", s)
	}

	// RHS: [tls://]DOMAIN[:PORT] — no wildcards allowed.
	useTLS := strings.HasPrefix(rhs, "tls://")
	rhs = strings.TrimPrefix(rhs, "tls://")
	if strings.Contains(rhs, "*") {
		return Entry{}, fmt.Errorf("wildcard not supported on RHS target in %q", s)
	}

	targetHost, targetPort := rhs, "443"
	if h, p, e := net.SplitHostPort(rhs); e == nil {
		if h == "" {
			return Entry{}, fmt.Errorf("empty host before ':' in %q", s)
		}
		if p == "" {
			return Entry{}, fmt.Errorf("empty port after ':' in %q", s)
		}
		targetHost, targetPort = h, p
	}
	targetHost = strings.ToLower(targetHost)
	route := Route{
		TargetAddr:   net.JoinHostPort(targetHost, targetPort),
		TargetDomain: targetHost,
		UseTLS:       useTLS,
	}

	// LHS: [*.]HOST[:PORT]
	isWildcard := strings.HasPrefix(lhs, wildcardPrefix)

	listenHost, listenPort := lhs, "443"
	if h, p, e := net.SplitHostPort(lhs); e == nil {
		if h == "" {
			return Entry{}, fmt.Errorf("empty host before ':' in %q", s)
		}
		if p == "" {
			return Entry{}, fmt.Errorf("empty port after ':' in %q", s)
		}
		listenHost, listenPort = h, p
	}
	listenHost = strings.ToLower(listenHost)

	if !isWildcard {
		if strings.Contains(listenHost, "*") {
			return Entry{}, fmt.Errorf("wildcard must be a leading '*.' on LHS in %q", s)
		}
		return Entry{
			Wildcard: false,
			Key:      net.JoinHostPort(listenHost, listenPort),
			Route:    route,
		}, nil
	}

	// Wildcard path: suffix must start with "." and contain no further "*".
	suffix := strings.TrimPrefix(listenHost, "*")
	if suffix == "" || suffix == "." {
		return Entry{}, fmt.Errorf("wildcard must include a domain after '*.' in %q", s)
	}
	if !strings.HasPrefix(suffix, ".") {
		return Entry{}, fmt.Errorf("wildcard prefix must be '*.' in %q", s)
	}
	if strings.Contains(suffix[1:], "*") {
		return Entry{}, fmt.Errorf("only a single leading '*.' is supported in %q", s)
	}
	return Entry{
		Wildcard: true,
		Suffix:   suffix,
		Port:     listenPort,
		Route:    route,
	}, nil
}

// ParseTunnelFlags parses multiple --tunnel values into a RouteTable.
// Duplicate exact routes or duplicate (wildcard-suffix, port) pairs yield an
// error. Exact and wildcard routes that may overlap on the same port are
// allowed — Lookup resolves exact-first.
func ParseTunnelFlags(flags []string) (*RouteTable, error) {
	t := NewRouteTable()
	for _, f := range flags {
		e, err := ParseTunnelFlag(f)
		if err != nil {
			return nil, fmt.Errorf("--tunnel %s: %w", f, err)
		}
		if !e.Wildcard {
			if err := t.addExact(e.Key, e.Route); err != nil {
				return nil, fmt.Errorf("--tunnel: %w", err)
			}
			continue
		}
		pattern := wildcardPrefix + strings.TrimPrefix(e.Suffix, ".")
		if err := t.addWildcard(e.Suffix, e.Port, e.Route, pattern); err != nil {
			return nil, fmt.Errorf("--tunnel: %w", err)
		}
	}
	// Longest suffix first among wildcards, for deterministic match order.
	sort.SliceStable(t.wildcard, func(i, j int) bool {
		return len(t.wildcard[i].suffix) > len(t.wildcard[j].suffix)
	})
	return t, nil
}
