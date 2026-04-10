package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
)

// ServeCmd is the Kong command for the HTTP CONNECT proxy server.
type ServeCmd struct {
	Cert   string   `help:"mTLS client certificate file (optional)."`
	Key    string   `help:"mTLS client key file (optional)."`
	Tunnel []string `required:"" help:"HOST[:PORT]=DOMAIN[:PORT] mapping."`
	Listen string   `default:"127.0.0.1:4140" help:"Listen address."`
}

func (s *ServeCmd) Run() error {
	cert, err := loadOptionalKeyPair(s.Cert, s.Key)
	if err != nil {
		return err
	}

	routes, err := ParseTunnelFlags(s.Tunnel)
	if err != nil {
		return err
	}

	srv := &Server{
		Routes:     routes,
		ClientCert: cert,
	}

	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", ln.Addr())
	for key, route := range routes {
		log.Printf("  %s → %s (tls=%v)", key, route.TargetAddr, route.UseTLS)
	}
	return http.Serve(ln, srv)
}

// Server is an HTTP CONNECT proxy that routes traffic through tunnel endpoints.
type Server struct {
	Routes     map[string]Route
	ClientCert tls.Certificate
	// RootCAs overrides the system cert pool for outer TLS connections.
	// nil means use the system pool
	RootCAs *x509.CertPool
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}

	// Normalize the CONNECT target to host:port.
	connectHost, connectPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		connectHost = r.Host
		connectPort = "443"
	}
	routeKey := net.JoinHostPort(connectHost, connectPort)

	route, ok := srv.Routes[routeKey]
	if !ok {
		http.Error(w, "target not allowed", http.StatusForbidden)
		return
	}

	remote, err := dialRoute(route, srv.ClientCert, srv.RootCAs)
	if err != nil {
		log.Printf("dial %s failed: %v", route.TargetAddr, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = remote.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = remote.Close()
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) //nolint:errcheck
	log.Printf("tunnel established: %s → %s", routeKey, route.TargetAddr)

	pipe(client, remote)
}

// loadOptionalKeyPair loads an mTLS client keypair if both paths are provided,
// returns a zero-value certificate if neither is provided, and errors if only one is.
func loadOptionalKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" && keyPath == "" {
		return tls.Certificate{}, nil
	}
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("--cert and --key must both be provided or both omitted")
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}
