package proxy

import (
	"testing"
)

func TestParseTunnelFlag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKey   string
		wantRoute Route
		wantErr   bool
	}{
		{
			name:    "HTTPS: host only both sides",
			input:   "ghe.acmecorp.dev=vcs.cust-abc.circleci-tunnel.com",
			wantKey: "ghe.acmecorp.dev:443",
			wantRoute: Route{
				TargetAddr:   "vcs.cust-abc.circleci-tunnel.com:443",
				TargetDomain: "vcs.cust-abc.circleci-tunnel.com",
				UseTLS:       true,
			},
		},
		{
			name:    "SSH: explicit ports both sides",
			input:   "ghe.acmecorp.dev:22=vcs-ssh.cust-abc.circleci-tunnel.com:443",
			wantKey: "ghe.acmecorp.dev:22",
			wantRoute: Route{
				TargetAddr:   "vcs-ssh.cust-abc.circleci-tunnel.com:443",
				TargetDomain: "vcs-ssh.cust-abc.circleci-tunnel.com",
				UseTLS:       true,
			},
		},
		{
			name:    "plain TCP: non-443 RHS port",
			input:   "ghe.acmecorp.dev:22=vcs-ssh.tunnel.com:2222",
			wantKey: "ghe.acmecorp.dev:22",
			wantRoute: Route{
				TargetAddr:   "vcs-ssh.tunnel.com:2222",
				TargetDomain: "vcs-ssh.tunnel.com",
				UseTLS:       false,
			},
		},
		{
			name:    "LHS port explicit 443",
			input:   "ghe.acmecorp.dev:443=vcs.tunnel.com",
			wantKey: "ghe.acmecorp.dev:443",
			wantRoute: Route{
				TargetAddr:   "vcs.tunnel.com:443",
				TargetDomain: "vcs.tunnel.com",
				UseTLS:       true,
			},
		},
		{
			name:    "missing equals sign",
			input:   "ghe.acmecorp.dev",
			wantErr: true,
		},
		{
			name:    "empty LHS",
			input:   "=vcs.tunnel.com",
			wantErr: true,
		},
		{
			name:    "empty RHS",
			input:   "ghe.acmecorp.dev=",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "just equals",
			input:   "=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, route, err := ParseTunnelFlag(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got key=%q route=%+v", key, route)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tt.wantKey {
				t.Errorf("key: got %q, want %q", key, tt.wantKey)
			}
			if route != tt.wantRoute {
				t.Errorf("route: got %+v, want %+v", route, tt.wantRoute)
			}
		})
	}
}

func TestParseTunnelFlags(t *testing.T) {
	t.Run("multiple valid flags", func(t *testing.T) {
		routes, err := ParseTunnelFlags([]string{
			"ghe.internal=vcs.cust.tunnel.com",
			"ghe.internal:22=vcs-ssh.cust.tunnel.com:443",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(routes) != 2 {
			t.Fatalf("expected 2 routes, got %d", len(routes))
		}
		if _, ok := routes["ghe.internal:443"]; !ok {
			t.Error("missing route for ghe.internal:443")
		}
		if _, ok := routes["ghe.internal:22"]; !ok {
			t.Error("missing route for ghe.internal:22")
		}
	})

	t.Run("duplicate route rejected", func(t *testing.T) {
		_, err := ParseTunnelFlags([]string{
			"ghe.internal=vcs.tunnel.com",
			"ghe.internal=other.tunnel.com",
		})
		if err == nil {
			t.Fatal("expected error for duplicate route")
		}
	})

	t.Run("invalid flag rejected", func(t *testing.T) {
		_, err := ParseTunnelFlags([]string{"bad-flag"})
		if err == nil {
			t.Fatal("expected error for invalid flag")
		}
	})
}
