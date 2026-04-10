package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

const dialTimeout = 10 * time.Second

// dialRoute connects to the tunnel endpoint for the given route.
func dialRoute(route Route, cert tls.Certificate, rootCAs *x509.CertPool) (net.Conn, error) {
	if route.UseTLS {
		conn, err := net.DialTimeout("tcp", route.TargetAddr, dialTimeout)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   route.TargetDomain,
			RootCAs:      rootCAs,
			MinVersion:   tls.VersionTLS13,
		})
		_ = conn.SetDeadline(time.Now().Add(dialTimeout))
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	return net.DialTimeout("tcp", route.TargetAddr, dialTimeout)
}
