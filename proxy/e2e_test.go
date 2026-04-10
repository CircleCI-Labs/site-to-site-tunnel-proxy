package proxy_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/circleci/backplane-go/testing/compiler"
)

var tunnelProxyBin string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	ctx := context.Background()

	p := compiler.NewParallel(1)
	defer p.Cleanup()

	p.Add(compiler.Work{
		Result: &tunnelProxyBin,
		Name:   "tunnel-proxy",
		Target: "..",
		Source: "github.com/circleci/site-to-site-tunnel-proxy/cmd/tunnel-proxy",
	})

	if err := p.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		return 1
	}

	return m.Run()
}

// writeDummyCert writes a self-signed cert/key pair to disk.
func writeDummyCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dummy"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = fmt.Sprintf("%s/cert.pem", dir)
	keyPath = fmt.Sprintf("%s/key.pem", dir)
	os.WriteFile(certPath, certPEM, 0600) //nolint:errcheck
	os.WriteFile(keyPath, keyPEM, 0600)   //nolint:errcheck
	return
}

func startTCPEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) //nolint:errcheck
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startServe launches the proxy binary with --listen 127.0.0.1:0 and returns
// the actual address by parsing the "listening on <addr>" log line from stderr.
// This avoids the TOCTOU port-reuse race.
func startServe(t *testing.T, extraArgs ...string) string {
	t.Helper()

	certPath, keyPath := writeDummyCert(t)

	args := []string{"serve", "--cert", certPath, "--key", keyPath, "--listen", "127.0.0.1:0"}
	args = append(args, extraArgs...)

	cmd := exec.Command(tunnelProxyBin, args...)
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	// Read stderr lines until we find "listening on <addr>".
	scanner := bufio.NewScanner(stderrPipe)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "listening on "); idx >= 0 {
			return line[idx+len("listening on "):]
		}
	}
	t.Fatal("proxy never logged listening address")
	return ""
}

func TestE2E_ServeThenCONNECT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	echoAddr := startTCPEchoServer(t)
	proxyAddr := startServe(t, "--tunnel", fmt.Sprintf("ghe.internal:8080=%s", echoAddr))

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT ghe.internal:8080 HTTP/1.1\r\nHost: ghe.internal:8080\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT got %d", resp.StatusCode)
	}

	msg := []byte("e2e serve test")
	conn.Write(msg) //nolint:errcheck
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if string(buf[:n]) != "e2e serve test" {
		t.Errorf("got %q", buf[:n])
	}
}

func TestE2E_ServeRejectsUnknownHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	echoAddr := startTCPEchoServer(t)
	proxyAddr := startServe(t, "--tunnel", fmt.Sprintf("allowed.host:8080=%s", echoAddr))

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT evil.host:443 HTTP/1.1\r\nHost: evil.host:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

func TestE2E_Connect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	certPath, keyPath := writeDummyCert(t)
	echoAddr := startTCPEchoServer(t)

	cmd := exec.Command(tunnelProxyBin, "connect",
		"--cert", certPath,
		"--key", keyPath,
		"--tunnel", fmt.Sprintf("ghe.internal:8080=%s", echoAddr),
		"ghe.internal:8080",
	)

	stdinPipe, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	msg := []byte("e2e connect test")
	go stdinPipe.Write(msg) //nolint:errcheck

	buf := make([]byte, 64)
	n, err := stdoutPipe.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "e2e connect test" {
		t.Errorf("got %q", buf[:n])
	}

	stdinPipe.Close()
}

func TestE2E_ServeThenCONNECT_NoCert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	echoAddr := startTCPEchoServer(t)

	cmd := exec.Command(tunnelProxyBin, "serve",
		"--listen", "127.0.0.1:0",
		"--tunnel", fmt.Sprintf("ghe.internal:8080=%s", echoAddr),
	)
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	var proxyAddr string
	scanner := bufio.NewScanner(stderrPipe)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "listening on "); idx >= 0 {
			proxyAddr = line[idx+len("listening on "):]
			break
		}
	}
	if proxyAddr == "" {
		t.Fatal("proxy never logged listening address")
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT ghe.internal:8080 HTTP/1.1\r\nHost: ghe.internal:8080\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT got %d", resp.StatusCode)
	}

	msg := []byte("no-cert e2e test")
	conn.Write(msg) //nolint:errcheck
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if string(buf[:n]) != "no-cert e2e test" {
		t.Errorf("got %q", buf[:n])
	}
}

func TestE2E_Connect_NoCert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	echoAddr := startTCPEchoServer(t)

	cmd := exec.Command(tunnelProxyBin, "connect",
		"--tunnel", fmt.Sprintf("ghe.internal:8080=%s", echoAddr),
		"ghe.internal:8080",
	)

	stdinPipe, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	msg := []byte("no-cert connect test")
	go stdinPipe.Write(msg) //nolint:errcheck

	buf := make([]byte, 64)
	n, err := stdoutPipe.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "no-cert connect test" {
		t.Errorf("got %q", buf[:n])
	}

	stdinPipe.Close()
}

func TestE2E_Version(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	out, err := exec.Command(tunnelProxyBin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v\n%s", err, out)
	}
	if len(out) == 0 {
		t.Fatal("version output is empty")
	}
}
