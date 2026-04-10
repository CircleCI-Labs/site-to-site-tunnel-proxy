package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
)

func TestConnectCmd_RouteNotFound(t *testing.T) {
	err := connectToTarget("unknown.host:443", tls.Certificate{}, map[string]Route{}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing route")
	}
}

func TestConnectCmd_BareHostDefaultsTo443(t *testing.T) {
	routes := map[string]Route{
		"ghe.internal:443": {TargetAddr: "127.0.0.1:1", UseTLS: false},
	}
	err := connectToTarget("ghe.internal", tls.Certificate{}, routes, nil, nil, nil)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if err.Error() == "no tunnel route for ghe.internal:443" {
		t.Fatal("route lookup failed — bare host not normalized to :443")
	}
}

func TestConnectCmd_ConnectionRefused(t *testing.T) {
	routes := map[string]Route{
		"ghe.internal:443": {TargetAddr: "127.0.0.1:1", UseTLS: false},
	}
	err := connectToTarget("ghe.internal:443", tls.Certificate{}, routes, nil, nil, nil)
	if err == nil {
		t.Fatal("refused connection produced no error")
	}
}

func TestConnectCmd_PlainTCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	msg := "hello from server"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte(msg)) //nolint:errcheck
	}()

	routes := map[string]Route{
		"internal.host:8080": {TargetAddr: ln.Addr().String(), UseTLS: false},
	}

	pr, pw := io.Pipe()
	defer pr.Close()

	go func() {
		connectToTarget("internal.host:8080", tls.Certificate{}, routes, nil, pr, pw) //nolint:errcheck
	}()

	buf := make([]byte, 64)
	n, err := pr.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}
}

func TestConnectCmd_TLSConnectWithoutClientCert(t *testing.T) {
	endpointAddr, endpointCACert := startTLSEndpoint(t)

	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	routes := map[string]Route{
		"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
	}

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	defer stdinR.Close()
	defer stdoutR.Close()

	go func() {
		connectToTarget("ghe.internal:443", tls.Certificate{}, routes, endpointCAPool, stdinR, stdoutW) //nolint:errcheck
		stdoutW.Close()
	}()

	msg := []byte("no mTLS payload")
	go stdinW.Write(msg) //nolint:errcheck

	buf := make([]byte, 64)
	n, err := stdoutR.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "no mTLS payload" {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}

	stdinW.Close()
}

func TestConnectCmd_TLSConnectWithMTLS(t *testing.T) {
	clientCA := newTestCA(t)
	endpointAddr, endpointCACert, _ := startMTLSEndpoint(t, clientCA.CAPool)

	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	routes := map[string]Route{
		"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
	}

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	defer stdinR.Close()
	defer stdoutR.Close()

	go func() {
		connectToTarget("ghe.internal:443", clientCA.Leaf, routes, endpointCAPool, stdinR, stdoutW) //nolint:errcheck
		stdoutW.Close()
	}()

	msg := []byte("test payload")
	go stdinW.Write(msg) //nolint:errcheck

	buf := make([]byte, 64)
	n, err := stdoutR.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "test payload" {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}

	stdinW.Close()
}
