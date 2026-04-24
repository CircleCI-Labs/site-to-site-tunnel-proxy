package proxy

import (
	"strings"
	"testing"
)

func TestParseTunnelFlag(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Entry
		wantErr string // substring to look for; "" = no error expected
	}{
		{
			name:  "plain TCP: host only both sides (no tls:// prefix)",
			input: "ghe.acmecorp.dev=vcs.cust-abc.example.com",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:443",
				Route: Route{
					TargetAddr:   "vcs.cust-abc.example.com:443",
					TargetDomain: "vcs.cust-abc.example.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "plain TCP: SSH explicit ports (no tls:// prefix)",
			input: "ghe.acmecorp.dev:22=vcs-ssh.cust-abc.example.com:443",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:22",
				Route: Route{
					TargetAddr:   "vcs-ssh.cust-abc.example.com:443",
					TargetDomain: "vcs-ssh.cust-abc.example.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "plain TCP: non-443 RHS port",
			input: "ghe.acmecorp.dev:22=vcs-ssh.tunnel.com:2222",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:22",
				Route: Route{
					TargetAddr:   "vcs-ssh.tunnel.com:2222",
					TargetDomain: "vcs-ssh.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "plain TCP: LHS port 443 does not affect RHS TLS",
			input: "ghe.acmecorp.dev:443=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "tls:// prefix enables TLS (no explicit port)",
			input: "ghe.acmecorp.dev=tls://vcs.cust-abc.example.com",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:443",
				Route: Route{
					TargetAddr:   "vcs.cust-abc.example.com:443",
					TargetDomain: "vcs.cust-abc.example.com",
					UseTLS:       true,
				},
			},
		},
		{
			name:  "tls:// prefix enables TLS (explicit port)",
			input: "ghe.acmecorp.dev:22=tls://vcs-ssh.cust-abc.example.com:443",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:22",
				Route: Route{
					TargetAddr:   "vcs-ssh.cust-abc.example.com:443",
					TargetDomain: "vcs-ssh.cust-abc.example.com",
					UseTLS:       true,
				},
			},
		},
		{
			name:  "LHS uppercase is lowercased",
			input: "GHE.AcmeCorp.Dev=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "ghe.acmecorp.dev:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},

		// ---- wildcard forms ----

		{
			name:  "wildcard: plain TCP, default port",
			input: "*.acmecorp.dev=vcs.tunnel.com",
			want: Entry{
				Wildcard: true,
				Suffix:   ".acmecorp.dev",
				Port:     "443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "wildcard: explicit LHS port",
			input: "*.acmecorp.dev:22=vcs-ssh.tunnel.com:2222",
			want: Entry{
				Wildcard: true,
				Suffix:   ".acmecorp.dev",
				Port:     "22",
				Route: Route{
					TargetAddr:   "vcs-ssh.tunnel.com:2222",
					TargetDomain: "vcs-ssh.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "wildcard: tls://",
			input: "*.acmecorp.dev=tls://vcs.tunnel.com:443",
			want: Entry{
				Wildcard: true,
				Suffix:   ".acmecorp.dev",
				Port:     "443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       true,
				},
			},
		},
		{
			name:  "wildcard: uppercase LHS lowered",
			input: "*.AcmeCorp.DEV=vcs.tunnel.com",
			want: Entry{
				Wildcard: true,
				Suffix:   ".acmecorp.dev",
				Port:     "443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},

		// ---- error cases ----

		{name: "missing equals sign", input: "ghe.acmecorp.dev", wantErr: "missing '='"},
		{name: "empty LHS", input: "=vcs.tunnel.com", wantErr: "empty LHS or RHS"},
		{name: "empty RHS", input: "ghe.acmecorp.dev=", wantErr: "empty LHS or RHS"},
		{name: "empty string", input: "", wantErr: "missing '='"},
		{name: "just equals", input: "=", wantErr: "empty LHS or RHS"},

		{name: "wildcard on RHS rejected", input: "*.acmecorp.dev=*.tunnel.com", wantErr: "wildcard not supported on RHS"},
		{name: "star alone on LHS", input: "*=vcs.tunnel.com", wantErr: "wildcard must be a leading '*.'"},
		{name: "star dot alone on LHS", input: "*.=vcs.tunnel.com", wantErr: "domain after '*.'"},
		{name: "star not leading", input: "ghe-*.internal=vcs.tunnel.com", wantErr: "wildcard must be a leading '*.'"},
		{name: "multiple stars", input: "*.*.acmecorp.dev=vcs.tunnel.com", wantErr: "only a single leading '*.'"},

		// ---- malformed host:port on either side ----

		{name: "wildcard LHS trailing colon (empty port)", input: "*.acmecorp.dev:=vcs.tunnel.com", wantErr: "empty port"},
		{name: "exact LHS trailing colon (empty port)", input: "ghe.acmecorp.dev:=vcs.tunnel.com", wantErr: "empty port"},
		{name: "RHS trailing colon (empty port)", input: "ghe.acmecorp.dev=vcs.tunnel.com:", wantErr: "empty port"},
		{name: "RHS tls:// trailing colon (empty port)", input: "ghe.acmecorp.dev=tls://vcs.tunnel.com:", wantErr: "empty port"},
		{name: "LHS leading colon (empty host)", input: ":443=vcs.tunnel.com", wantErr: "empty host"},
		{name: "RHS leading colon (empty host)", input: "ghe.acmecorp.dev=:443", wantErr: "empty host"},

		// ---- non-FQDN hosts: parser must accept these as-is ----

		{
			name:  "IPv4 LHS with explicit port",
			input: "192.168.1.1:443=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "192.168.1.1:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "IPv4 LHS bare (defaults to :443)",
			input: "192.168.1.1=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "192.168.1.1:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "IPv6 LHS with explicit port",
			input: "[::1]:443=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "[::1]:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
		{
			name:  "punycode LHS (ASCII IDN) round-trips",
			input: "xn--nxasmq6b.example=vcs.tunnel.com",
			want: Entry{
				Wildcard: false,
				Key:      "xn--nxasmq6b.example:443",
				Route: Route{
					TargetAddr:   "vcs.tunnel.com:443",
					TargetDomain: "vcs.tunnel.com",
					UseTLS:       false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTunnelFlag(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got entry=%+v", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error: got %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("entry: got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseTunnelFlags(t *testing.T) {
	t.Run("multiple valid flags", func(t *testing.T) {
		rt, err := ParseTunnelFlags([]string{
			"ghe.internal=vcs.cust.tunnel.com",
			"ghe.internal:22=vcs-ssh.cust.tunnel.com:443",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rt.Len() != 2 {
			t.Fatalf("expected 2 routes, got %d", rt.Len())
		}
		if _, ok := rt.Lookup("ghe.internal", "443"); !ok {
			t.Error("missing route for ghe.internal:443")
		}
		if _, ok := rt.Lookup("ghe.internal", "22"); !ok {
			t.Error("missing route for ghe.internal:22")
		}
	})

	t.Run("duplicate exact route rejected", func(t *testing.T) {
		_, err := ParseTunnelFlags([]string{
			"ghe.internal=vcs.tunnel.com",
			"ghe.internal=other.tunnel.com",
		})
		if err == nil {
			t.Fatal("expected error for duplicate exact route")
		}
	})

	t.Run("duplicate wildcard route rejected", func(t *testing.T) {
		_, err := ParseTunnelFlags([]string{
			"*.acmecorp.dev=vcs.tunnel.com",
			"*.acmecorp.dev=other.tunnel.com",
		})
		if err == nil {
			t.Fatal("expected error for duplicate wildcard route")
		}
	})

	t.Run("same wildcard suffix different ports allowed", func(t *testing.T) {
		rt, err := ParseTunnelFlags([]string{
			"*.acmecorp.dev=vcs.tunnel.com",
			"*.acmecorp.dev:22=vcs-ssh.tunnel.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rt.Len() != 2 {
			t.Fatalf("expected 2 routes, got %d", rt.Len())
		}
	})

	t.Run("exact and wildcard can coexist", func(t *testing.T) {
		rt, err := ParseTunnelFlags([]string{
			"*.acmecorp.dev=wild.tunnel.com",
			"ghe.acmecorp.dev=exact.tunnel.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rt.Len() != 2 {
			t.Fatalf("expected 2 routes, got %d", rt.Len())
		}
	})

	t.Run("invalid flag rejected", func(t *testing.T) {
		_, err := ParseTunnelFlags([]string{"bad-flag"})
		if err == nil {
			t.Fatal("expected error for invalid flag")
		}
	})
}

func TestRouteTable_Lookup(t *testing.T) {
	rt, err := ParseTunnelFlags([]string{
		"ghe.acmecorp.dev=exact.tunnel.com",
		"*.acmecorp.dev=wild.tunnel.com",
		"*.internal.acmecorp.dev=deep.tunnel.com",
		"*.ssh.acmecorp.dev:22=ssh.tunnel.com:2222",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	cases := []struct {
		name       string
		host, port string
		wantOK     bool
		wantAddr   string
	}{
		{name: "exact beats wildcard", host: "ghe.acmecorp.dev", port: "443", wantOK: true, wantAddr: "exact.tunnel.com:443"},
		{name: "wildcard single label", host: "foo.acmecorp.dev", port: "443", wantOK: true, wantAddr: "wild.tunnel.com:443"},
		{name: "wildcard deep label", host: "a.b.acmecorp.dev", port: "443", wantOK: true, wantAddr: "wild.tunnel.com:443"},
		{name: "longest suffix wins", host: "foo.internal.acmecorp.dev", port: "443", wantOK: true, wantAddr: "deep.tunnel.com:443"},
		{name: "apex does not match wildcard", host: "acmecorp.dev", port: "443", wantOK: false},
		{name: "port-scoped wildcard: wrong port", host: "foo.ssh.acmecorp.dev", port: "443", wantOK: true, wantAddr: "wild.tunnel.com:443"}, // falls through to *.acmecorp.dev:443
		{name: "port-scoped wildcard: right port", host: "foo.ssh.acmecorp.dev", port: "22", wantOK: true, wantAddr: "ssh.tunnel.com:2222"},
		{name: "case-insensitive host", host: "FOO.ACMECORP.DEV", port: "443", wantOK: true, wantAddr: "wild.tunnel.com:443"},
		{name: "unrelated host: no match", host: "example.com", port: "443", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := rt.Lookup(tc.host, tc.port)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v (route=%+v)", ok, tc.wantOK, r)
			}
			if ok && r.TargetAddr != tc.wantAddr {
				t.Errorf("target: got %q, want %q", r.TargetAddr, tc.wantAddr)
			}
		})
	}
}

func TestRouteTable_NilSafe(t *testing.T) {
	var rt *RouteTable
	if _, ok := rt.Lookup("anything", "443"); ok {
		t.Error("nil RouteTable should not resolve")
	}
	if rt.Len() != 0 {
		t.Error("nil RouteTable Len should be 0")
	}
	if rt.Exact() != nil {
		t.Error("nil RouteTable Exact should be nil")
	}
	if rt.Wildcards() != nil {
		t.Error("nil RouteTable Wildcards should be nil")
	}
}
