package proxy

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestServer_RejectsNonCONNECT(t *testing.T) {
	addr := startProxy(t, &Server{Routes: map[string]Route{}})

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestServer_RejectsUnknownHost(t *testing.T) {
	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"allowed.host:443": {TargetAddr: "127.0.0.1:9999", UseTLS: false},
		},
	})
	connectExpectStatus(t, addr, "evil.host:443", http.StatusForbidden)
}

func TestServer_PlainTCPTunnel(t *testing.T) {
	echoAddr := startEchoServer(t)
	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"internal.host:8080": {TargetAddr: echoAddr, UseTLS: false},
		},
	})
	connectAndEcho(t, addr, "internal.host:8080", "hello tunnel")
}

func TestServer_TLSTunnelWithMTLS(t *testing.T) {
	clientCA := newTestCA(t)
	endpointAddr, endpointCACert, _ := startMTLSEndpoint(t, clientCA.CAPool)

	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
		},
		ClientCert: clientCA.Leaf,
		RootCAs:    endpointCAPool,
	})
	connectAndEcho(t, addr, "ghe.internal:443", "inner TLS payload")
}

func TestServer_TLSTunnelWithoutClientCert(t *testing.T) {
	endpointAddr, endpointCACert := startTLSEndpoint(t)

	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
		},
		// ClientCert intentionally zero value — no mTLS.
		RootCAs: endpointCAPool,
	})
	connectAndEcho(t, addr, "ghe.internal:443", "no client cert")
}

func TestServer_MultiRoute(t *testing.T) {
	echo1 := startEchoServer(t)
	echo2 := startEchoServer(t)

	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"host-a:443": {TargetAddr: echo1, UseTLS: false},
			"host-b:22":  {TargetAddr: echo2, UseTLS: false},
		},
	})
	connectAndEcho(t, addr, "host-a:443", "from-a")
	connectAndEcho(t, addr, "host-b:22", "from-b")
}

func TestServer_ConnectionRefused(t *testing.T) {
	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"dead.host:443": {TargetAddr: "127.0.0.1:1", UseTLS: false},
		},
	})
	connectExpectStatus(t, addr, "dead.host:443", http.StatusBadGateway)
}

func TestServer_WrongClientCA(t *testing.T) {
	// Endpoint trusts CA-A. Proxy presents a cert signed by CA-B.
	//
	// With TLS 1.3, client cert verification is deferred past the handshake,
	// so tls.Dial may "succeed". We verify the tunnel is non-functional:
	// either CONNECT returns 502 or the data path breaks.
	caA := newTestCA(t)
	caB := newTestCA(t)
	endpointAddr, endpointCACert, _ := startMTLSEndpoint(t, caA.CAPool)

	endpointCAPool := x509.NewCertPool()
	endpointCAPool.AddCert(endpointCACert)

	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"ghe.internal:443": {TargetAddr: endpointAddr, TargetDomain: "127.0.0.1", UseTLS: true},
		},
		ClientCert: caB.Leaf,
		RootCAs:    endpointCAPool,
	})

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT ghe.internal:443 HTTP/1.1\r\nHost: ghe.internal:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode == http.StatusBadGateway {
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// TLS 1.3 path: CONNECT returned 200, but the server will kill the
	// connection once it processes the bad client cert.
	conn.Write([]byte("should not echo")) //nolint:errcheck
	buf := make([]byte, 64)
	_, err = br.Read(buf)
	if err == nil {
		t.Fatal("expected read error (wrong CA should kill connection), but got data")
	}
}

func TestServer_DefaultPortNormalization(t *testing.T) {
	echoAddr := startEchoServer(t)
	addr := startProxy(t, &Server{
		Routes: map[string]Route{
			"ghe.internal:443": {TargetAddr: echoAddr, UseTLS: false},
		},
	})
	connectAndEcho(t, addr, "ghe.internal:443", "ok")
}
