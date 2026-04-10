package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
)

// ConnectCmd is the Kong command for stdio connect mode (SSH ProxyCommand).
type ConnectCmd struct {
	Cert   string   `help:"mTLS client certificate file (optional)."`
	Key    string   `help:"mTLS client key file (optional)."`
	Tunnel []string `required:"" help:"HOST[:PORT]=DOMAIN[:PORT] mapping."`
	Target string   `arg:"" help:"host:port to connect to."`
}

func (c *ConnectCmd) Run() error {
	cert, err := loadOptionalKeyPair(c.Cert, c.Key)
	if err != nil {
		return err
	}

	routes, err := ParseTunnelFlags(c.Tunnel)
	if err != nil {
		return err
	}

	return connectToTarget(c.Target, cert, routes, nil, os.Stdin, os.Stdout)
}

// connectToTarget dials the tunnel endpoint for the given target and pipes r/w through it.
func connectToTarget(target string, cert tls.Certificate, routes map[string]Route, rootCAs *x509.CertPool, r io.Reader, w io.Writer) error {
	host, port, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		host = target
		port = "443"
	}
	routeKey := net.JoinHostPort(host, port)

	route, ok := routes[routeKey]
	if !ok {
		return fmt.Errorf("no tunnel route for %s", routeKey)
	}

	remote, err := dialRoute(route, cert, rootCAs)
	if err != nil {
		return fmt.Errorf("dial %s: %w", route.TargetAddr, err)
	}

	// Copy in both directions. When one side closes, close the
	// connection to unblock the other.
	done := make(chan struct{})
	go func() {
		io.Copy(remote, r) //nolint:errcheck
		_ = remote.Close()
		close(done)
	}()
	io.Copy(w, remote) //nolint:errcheck
	_ = remote.Close()
	<-done
	return nil
}
