package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeCmd_Integration(t *testing.T) {
	ca, certPath, keyPath := writeCertFiles(t)

	endpointAddr, endpointCACert, _ := startMTLSEndpoint(t, ca.CAPool)
	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}

	addr := startProxy(t, &Server{
		Routes: exactTable(map[string]Route{
			"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
		}),
		ClientCert: cert,
		RootCAs:    endpointCAPool,
	})
	connectAndEcho(t, addr, "ghe.internal:443", "integration test")
}

func TestServeCmd_BadCertFile(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad.crt")
	badKey := filepath.Join(dir, "bad.key")
	os.WriteFile(badCert, []byte("not a cert"), 0600) //nolint:errcheck
	os.WriteFile(badKey, []byte("not a key"), 0600)   //nolint:errcheck

	err := (&ServeCmd{Cert: badCert, Key: badKey, Tunnel: []string{"host=domain"}, Listen: "127.0.0.1:0"}).Run()
	if err == nil {
		t.Fatal("expected error for bad cert files")
	}
}

func TestServeCmd_BadTunnelFlag(t *testing.T) {
	_, certPath, keyPath := writeCertFiles(t)

	err := (&ServeCmd{Cert: certPath, Key: keyPath, Tunnel: []string{"no-equals-sign"}, Listen: "127.0.0.1:0"}).Run()
	if err == nil {
		t.Fatal("expected error for bad tunnel flag")
	}
}

func TestConnectCmd_Integration(t *testing.T) {
	ca, certPath, keyPath := writeCertFiles(t)

	endpointAddr, endpointCACert, _ := startMTLSEndpoint(t, ca.CAPool)
	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	routes := exactTable(map[string]Route{
		"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
	})

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		connectToTarget("ghe.internal:443", cert, routes, endpointCAPool, stdinR, stdoutW) //nolint:errcheck
		stdoutW.Close()
	}()

	msg := []byte("integration connect test")
	go stdinW.Write(msg) //nolint:errcheck

	buf := make([]byte, 64)
	n, err := stdoutR.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "integration connect test" {
		t.Errorf("got %q", buf[:n])
	}

	stdinW.Close()
	stdoutR.Close()
}

func TestConnectCmd_BadCertFile(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad.crt")
	badKey := filepath.Join(dir, "bad.key")
	os.WriteFile(badCert, []byte("not a cert"), 0600) //nolint:errcheck
	os.WriteFile(badKey, []byte("not a key"), 0600)   //nolint:errcheck

	err := (&ConnectCmd{Cert: badCert, Key: badKey, Tunnel: []string{"host=domain"}, Target: "host:443"}).Run()
	if err == nil {
		t.Fatal("expected error for bad cert files")
	}
}

func TestConnectCmd_BadTunnelFlag(t *testing.T) {
	_, certPath, keyPath := writeCertFiles(t)

	err := (&ConnectCmd{Cert: certPath, Key: keyPath, Tunnel: []string{"no-equals-sign"}, Target: "host:443"}).Run()
	if err == nil {
		t.Fatal("expected error for bad tunnel flag")
	}
}

func TestServeCmd_NoCertKey_ParsesTunnelFlags(t *testing.T) {
	// With no --cert/--key provided, cert loading should be skipped and
	// tunnel-flag parsing should run. A bad flag surfaces a tunnel parse error.
	err := (&ServeCmd{Tunnel: []string{"no-equals-sign"}, Listen: "127.0.0.1:0"}).Run()
	if err == nil {
		t.Fatal("expected error for bad tunnel flag")
	}
	if !strings.Contains(err.Error(), "missing '='") {
		t.Errorf("expected tunnel parse error, got: %v", err)
	}
}

func TestConnectCmd_NoCertKey_ParsesTunnelFlags(t *testing.T) {
	err := (&ConnectCmd{Tunnel: []string{"no-equals-sign"}, Target: "host:443"}).Run()
	if err == nil {
		t.Fatal("expected error for bad tunnel flag")
	}
	if !strings.Contains(err.Error(), "missing '='") {
		t.Errorf("expected tunnel parse error, got: %v", err)
	}
}

func TestServeCmd_OnlyCertNoKey(t *testing.T) {
	err := (&ServeCmd{Cert: "/tmp/cert.pem", Tunnel: []string{"h=d"}, Listen: "127.0.0.1:0"}).Run()
	if err == nil {
		t.Fatal("expected error when only --cert is provided")
	}
	if !strings.Contains(err.Error(), "both be provided") {
		t.Errorf("expected both-be-provided error, got: %v", err)
	}
}

func TestConnectCmd_OnlyKeyNoCert(t *testing.T) {
	err := (&ConnectCmd{Key: "/tmp/key.pem", Tunnel: []string{"h=d"}, Target: "host:443"}).Run()
	if err == nil {
		t.Fatal("expected error when only --key is provided")
	}
	if !strings.Contains(err.Error(), "both be provided") {
		t.Errorf("expected both-be-provided error, got: %v", err)
	}
}
