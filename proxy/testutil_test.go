package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCAResult holds the outputs of newTestCA.
type testCAResult struct {
	CACert *x509.Certificate
	CAKey  *ecdsa.PrivateKey
	CAPool *x509.CertPool
	Leaf   tls.Certificate
}

// newTestCA generates a self-signed CA and a leaf certificate signed by it.
func newTestCA(t *testing.T) testCAResult {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyDER, _ := x509.MarshalECPrivateKey(leafKey)
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	leaf, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return testCAResult{
		CACert: caCert,
		CAKey:  caKey,
		CAPool: caPool,
		Leaf:   leaf,
	}
}

// writeCertFiles generates a CA + leaf and writes PEM files to a temp dir.
func writeCertFiles(t *testing.T) (ca testCAResult, certPath, keyPath string) {
	t.Helper()
	ca = newTestCA(t)
	dir := t.TempDir()

	// Re-extract the PEM from the leaf cert.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Leaf.Certificate[0]})
	keyDER, _ := x509.MarshalECPrivateKey(ca.Leaf.PrivateKey.(*ecdsa.PrivateKey))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	os.WriteFile(certPath, certPEM, 0600) //nolint:errcheck
	os.WriteFile(keyPath, keyPEM, 0600)   //nolint:errcheck
	return
}

// startEchoServer starts a plain TCP server that echoes data back.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptAndEcho(ln)
	return ln.Addr().String()
}

// startMTLSEndpoint starts a TLS 1.3 echo server requiring client certs.
// Returns the address, server CA cert, and server CA key.
func startMTLSEndpoint(t *testing.T, clientCAPool *x509.CertPool) (addr string, serverCA *x509.Certificate, serverCAKey *ecdsa.PrivateKey) {
	t.Helper()

	// Generate server CA + leaf cert.
	serverCAKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Endpoint CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	serverCADER, _ := x509.CreateCertificate(rand.Reader, serverCATmpl, serverCATmpl, &serverCAKey.PublicKey, serverCAKey)
	serverCA, _ = x509.ParseCertificate(serverCADER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, serverCA, &srvKey.PublicKey, serverCAKey)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	srvTLS, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptAndEcho(ln)

	return ln.Addr().String(), serverCA, serverCAKey
}

// startTLSEndpoint starts a TLS 1.3 echo server with server auth only
// (no client cert required). Returns the address and the server CA cert.
func startTLSEndpoint(t *testing.T) (addr string, serverCA *x509.Certificate) {
	t.Helper()

	serverCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Endpoint CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	serverCADER, _ := x509.CreateCertificate(rand.Reader, serverCATmpl, serverCATmpl, &serverCAKey.PublicKey, serverCAKey)
	serverCA, _ = x509.ParseCertificate(serverCADER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, serverCA, &srvKey.PublicKey, serverCAKey)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	srvTLS, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvTLS},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptAndEcho(ln)

	return ln.Addr().String(), serverCA
}

// startProxy starts an HTTP server for the given Server and returns its address.
func startProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, srv) //nolint:errcheck
	return ln.Addr().String()
}

// connectAndEcho sends a CONNECT request through the proxy, writes msg,
// reads the echo, and asserts it matches.
func connectAndEcho(t *testing.T, proxyAddr, connectTarget, msg string) {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTarget, connectTarget)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT %s: got %d, want 200", connectTarget, resp.StatusCode)
	}

	conn.Write([]byte(msg)) //nolint:errcheck
	buf := make([]byte, len(msg)+32)
	n, err := br.Read(buf)
	if err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Errorf("echo: got %q, want %q", buf[:n], msg)
	}
}

// connectExpectStatus sends a CONNECT request and asserts the response status code.
func connectExpectStatus(t *testing.T, proxyAddr, connectTarget string, wantStatus int) {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTarget, connectTarget)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Errorf("CONNECT %s: got %d, want %d", connectTarget, resp.StatusCode, wantStatus)
	}
}

func acceptAndEcho(ln net.Listener) {
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
}
