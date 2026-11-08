package edgediscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type connectProxyRecord struct {
	target string
	auth   string
}

func TestDialEdgeViaProxyUsesAuthenticatedConnectAndPreservesSNI(t *testing.T) {
	t.Parallel()

	edgeHeaders := make(chan http.Header, 1)
	edgeServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		edgeHeaders <- request.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer edgeServer.Close()
	sni := make(chan string, 1)
	edgeServer.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni <- hello.ServerName
		return nil, nil
	}
	edgeAddr := edgeServer.Listener.Addr().(*net.TCPAddr)

	proxyURL, proxyRecords := startTestConnectProxy(t, edgeAddr.String(), http.StatusOK)
	proxyURL.User = url.UserPassword("proxy-user", "proxy-password")
	tlsConfig := edgeServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialEdgeViaProxy(ctx, 5*time.Second, tlsConfig, edgeAddr, nil, proxyURL)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, response.StatusCode)
	select {
	case headers := <-edgeHeaders:
		assert.Empty(t, headers.Get("Proxy-Authorization"))
	case <-ctx.Done():
		t.Fatal("edge did not receive tunneled HTTP request")
	}
	select {
	case gotSNI := <-sni:
		assert.Equal(t, "example.com", gotSNI)
	case <-ctx.Done():
		t.Fatal("edge TLS server did not receive a ClientHello")
	}
	select {
	case record := <-proxyRecords:
		assert.Equal(t, edgeAddr.String(), record.target)
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-password")), record.auth)
	case <-ctx.Done():
		t.Fatal("proxy did not receive CONNECT")
	}
}

func TestDialEdgeViaProxyRejectsNon200Response(t *testing.T) {
	t.Parallel()

	proxyURL, records := startTestConnectProxy(t, "", http.StatusForbidden)
	proxyURL.User = url.UserPassword("user", "secret")
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 7844}
	_, err := DialEdgeViaProxy(context.Background(), time.Second, &tls.Config{}, addr, nil, proxyURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.NotContains(t, err.Error(), "secret")
	record := <-records
	assert.Equal(t, addr.String(), record.target)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")), record.auth)
}

func TestDialEdgeViaProxyDoesNotForwardTCPAddressZone(t *testing.T) {
	t.Parallel()

	proxyURL, records := startTestConnectProxy(t, "", http.StatusForbidden)
	addr := &net.TCPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 7844,
		Zone: "eth0\r\nProxy-Authorization: Basic injected",
	}
	_, err := DialEdgeViaProxy(context.Background(), time.Second, &tls.Config{}, addr, nil, proxyURL)
	require.Error(t, err)
	record := <-records
	assert.Equal(t, "[2001:db8::1]:7844", record.target)
	assert.Empty(t, record.auth)
}

func TestBufferedConnReadsBytesAlreadyBufferedByHTTPParser(t *testing.T) {
	t.Parallel()

	conn, peer := net.Pipe()
	defer func() { _ = conn.Close() }()
	defer func() { _ = peer.Close() }()
	buffered := &bufferedConn{Conn: conn, reader: bufio.NewReader(strings.NewReader("tunnel-data"))}
	got := make([]byte, len("tunnel-data"))
	_, err := io.ReadFull(buffered, got)
	require.NoError(t, err)
	assert.Equal(t, "tunnel-data", string(got))
}

func startTestConnectProxy(t *testing.T, upstream string, status int) (*url.URL, <-chan connectProxyRecord) {
	t.Helper()
	records := make(chan connectProxyRecord, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		records <- connectProxyRecord{target: request.Host, auth: request.Header.Get("Proxy-Authorization")}
		if request.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if request.Host != upstream {
			http.Error(w, "unexpected CONNECT target", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		clientConn, writer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = clientConn.Close() }()
		upstreamConn, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer func() { _ = upstreamConn.Close() }()
		if _, err := io.WriteString(writer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
		go func() { _, _ = io.Copy(upstreamConn, clientConn) }()
		_, _ = io.Copy(clientConn, upstreamConn)
	}))
	t.Cleanup(proxyServer.Close)
	proxyURL, err := url.Parse("http://" + proxyServer.Listener.Addr().String())
	require.NoError(t, err)
	return proxyURL, records
}
