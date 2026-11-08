package doh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/dnsproxy"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverQueriesThroughAuthenticatedProxy(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var queries []string
	var endpointRequests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		queries = append(queries, request.URL.Query().Get("name")+":"+request.URL.Query().Get("type"))
		endpointRequests++
		mu.Unlock()
		var answer string
		switch request.URL.Query().Get("type") {
		case "33":
			answer = `,"Answer":[{"type":5,"data":"srv.alias.example."},{"type":33,"data":"10 5 7844 edge1.example."},{"type":33,"data":"20 1 7845 edge2.example."}]`
		case "1":
			answer = `,"Answer":[{"type":5,"data":"a.alias.example."},{"type":1,"data":"192.0.2.10"}]`
		case "28":
			answer = `,"Answer":[{"type":5,"data":"aaaa.alias.example."},{"type":28,"data":"2001:db8::1"}]`
		case "16":
			answer = `,"Answer":[{"type":5,"data":"txt.alias.example."},{"type":16,"data":"feature-value"}]`
		default:
			t.Errorf("unexpected query type %q", request.URL.Query().Get("type"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"Status":0`+answer+`}`)
	}))
	defer server.Close()

	proxyURL, proxyAuth := startConnectProxy(t, server.Listener.Addr().String())
	proxyURL.User = url.UserPassword("user", "secret")
	resolver, err := newResolverWithTLS(proxyURL, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig)
	require.NoError(t, err)

	cname, srvRecords, err := resolver.LookupSRV(context.Background(), "origintunneld", "tcp", "argotunnel.com")
	require.NoError(t, err)
	assert.Equal(t, "_origintunneld._tcp.argotunnel.com", cname)
	require.Len(t, srvRecords, 2)
	assert.Equal(t, &net.SRV{Priority: 10, Weight: 5, Port: 7844, Target: "edge1.example."}, srvRecords[0])
	assert.Equal(t, &net.SRV{Priority: 20, Weight: 1, Port: 7845, Target: "edge2.example."}, srvRecords[1])

	ips, err := resolver.LookupIP(context.Background(), "edge1.example")
	require.NoError(t, err)
	assert.Equal(t, []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")}, ips)
	texts, err := resolver.LookupTXT(context.Background(), "cfd-features.argotunnel.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"feature-value"}, texts)

	mu.Lock()
	gotQueries := append([]string(nil), queries...)
	gotEndpointRequests := endpointRequests
	mu.Unlock()
	assert.ElementsMatch(t, []string{
		"_origintunneld._tcp.argotunnel.com:33",
		"edge1.example:1",
		"edge1.example:28",
		"cfd-features.argotunnel.com:16",
	}, gotQueries)
	assert.Equal(t, 4, gotEndpointRequests)
	select {
	case auth := <-proxyAuth:
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")), auth)
	default:
		t.Fatal("proxy did not receive authentication")
	}
}

func TestResolverExchangeUsesAuthenticatedWireDoH(t *testing.T) {
	t.Parallel()

	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	answer[3] |= 0x80
	requestBodies := make(chan []byte, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/dns-query", request.URL.Path)
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Equal(t, "application/dns-message", request.Header.Get("Content-Type"))
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read wire DNS request: %v", err)
			return
		}
		requestBodies <- body
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(answer); err != nil {
			t.Errorf("write wire DNS response: %v", err)
		}
	}))
	defer server.Close()

	proxyURL, proxyAuth := startConnectProxy(t, server.Listener.Addr().String())
	proxyURL.User = url.UserPassword("dns-user", "dns-secret")
	resolver, err := newResolverWithTLS(proxyURL, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig)
	require.NoError(t, err)
	t.Cleanup(resolver.client.CloseIdleConnections)
	got, err := resolver.Exchange(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, answer, got)
	assert.Equal(t, query, <-requestBodies)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("dns-user:dns-secret")), <-proxyAuth)
}

func TestResolverExchangeWithoutProxy(t *testing.T) {
	t.Parallel()

	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read wire DNS request: %v", err)
			return
		}
		assert.Equal(t, query, body)
		if _, err := w.Write(answer); err != nil {
			t.Errorf("write wire DNS response: %v", err)
		}
	}))
	defer server.Close()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	resolver, err := newResolverWithTLS(nil, server.URL, tlsConfig)
	require.NoError(t, err)
	t.Cleanup(resolver.client.CloseIdleConnections)

	got, err := resolver.Exchange(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, answer, got)
}

func TestUDPProxyForwardsWireDNSThroughAuthenticatedDoHProxy(t *testing.T) {
	t.Parallel()

	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	requestBodies := make(chan []byte, 1)
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/dns-query" || request.Method != http.MethodPost {
			http.Error(w, "unexpected DoH request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read DoH request: %v", err)
			return
		}
		requestBodies <- body
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(answer); err != nil {
			t.Errorf("write DoH response: %v", err)
		}
	}))
	defer httpsServer.Close()

	proxyURL, proxyAuth := startConnectProxy(t, httpsServer.Listener.Addr().String())
	proxyURL.User = url.UserPassword("dns-user", "dns-secret")
	resolver, err := newResolverWithTLS(proxyURL, httpsServer.URL, httpsServer.Client().Transport.(*http.Transport).TLSClientConfig)
	require.NoError(t, err)
	t.Cleanup(resolver.client.CloseIdleConnections)
	logger := zerolog.Nop()
	udpServer, err := dnsproxy.Listen(net.ParseIP("127.0.0.1"), 0, resolver, &logger)
	require.NoError(t, err)
	defer func() { _ = udpServer.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- udpServer.Serve(ctx) }()

	client, err := net.DialUDP("udp", nil, udpServer.Addr())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	_, err = client.Write(query)
	require.NoError(t, err)
	response := make([]byte, 512)
	n, err := client.Read(response)
	require.NoError(t, err)
	assert.Equal(t, answer, response[:n])
	assert.Equal(t, query, <-requestBodies)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("dns-user:dns-secret")), <-proxyAuth)

	cancel()
	select {
	case err := <-serveErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("UDP DNS proxy did not stop after context cancellation")
	}
}

func TestResolverReturnsDoHErrorsWithoutDirectFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "non-200", statusCode: http.StatusBadGateway, body: `{"Status":0}`},
		{name: "DNS error", statusCode: http.StatusOK, body: `{"Status":2}`},
		{name: "missing DNS status", statusCode: http.StatusOK, body: `{}`},
		{name: "malformed address", statusCode: http.StatusOK, body: `{"Status":0,"Answer":[{"type":1,"data":"not-an-ip"}]}`},
		{name: "malformed JSON", statusCode: http.StatusOK, body: `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var endpointRequests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				endpointRequests.Add(1)
				w.WriteHeader(test.statusCode)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			proxyURL, _ := startConnectProxy(t, server.Listener.Addr().String())
			resolver, err := newResolverWithTLS(proxyURL, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig)
			require.NoError(t, err)
			t.Cleanup(resolver.client.CloseIdleConnections)
			_, err = resolver.LookupIP(context.Background(), "example.invalid")
			require.Error(t, err)
			assert.NotZero(t, endpointRequests.Load())
		})
	}
}

func TestResolverDoesNotBypassFailedProxy(t *testing.T) {
	t.Parallel()

	var endpointRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		endpointRequests.Add(1)
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":16,"data":"\"feature\""}]}`)
	}))
	defer server.Close()
	proxyURL, _ := startConnectProxy(t, "127.0.0.1:1")
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	resolver, err := newResolverWithTLS(proxyURL, server.URL, tlsConfig)
	require.NoError(t, err)
	t.Cleanup(resolver.client.CloseIdleConnections)

	_, err = resolver.LookupTXT(context.Background(), "cfd-features.argotunnel.com")
	require.Error(t, err)
	assert.Zero(t, endpointRequests.Load())
}

func startConnectProxy(t *testing.T, upstream string) (*url.URL, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	authValues := make(chan string, 8)
	var connections sync.WaitGroup
	var active sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			client, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			active.Store(client, struct{}{})
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() {
					_ = client.Close()
					active.Delete(client)
				}()
				request, readErr := http.ReadRequest(bufio.NewReader(client))
				if readErr != nil {
					return
				}
				authValues <- request.Header.Get("Proxy-Authorization")
				if request.Method != http.MethodConnect || request.URL.Host != upstream {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				upstreamConn, dialErr := net.Dial("tcp", upstream)
				if dialErr != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				active.Store(upstreamConn, struct{}{})
				defer func() {
					_ = upstreamConn.Close()
					active.Delete(upstreamConn)
				}()
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(upstreamConn, client) }()
				_, _ = io.Copy(client, upstreamConn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		active.Range(func(conn, _ any) bool {
			_ = conn.(net.Conn).Close()
			return true
		})
		connections.Wait()
	})
	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, err)
	return proxyURL, authValues
}

func TestResolverRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := NewResolver(nil)
	require.Error(t, err)
	_, err = NewResolver(&url.URL{Scheme: "https", Host: "proxy.example"})
	require.Error(t, err)
}

func TestLookupIPAllowsOneSuccessfulFamily(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var requested []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		queryType := request.URL.Query().Get("type")
		mu.Lock()
		requested = append(requested, queryType)
		mu.Unlock()
		if queryType == strconv.Itoa(typeA) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, `{"Status":0,"Answer":[{"type":28,"data":"2001:db8::2"}]}`)
	}))
	defer server.Close()
	proxyURL, _ := startConnectProxy(t, server.Listener.Addr().String())
	resolver, err := newResolverWithTLS(proxyURL, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig)
	require.NoError(t, err)
	ips, err := resolver.LookupIP(context.Background(), "one-family.example")
	require.NoError(t, err)
	assert.Equal(t, []net.IP{net.ParseIP("2001:db8::2")}, ips)
	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, []string{"1", "28"}, requested)
}

func TestLookupTXTReturnsDNSJSONDataUnmodified(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":16,"data":"unquoted"},{"type":16,"data":"\"quoted text\""}]}`)
	}))
	defer server.Close()
	proxyURL, _ := startConnectProxy(t, server.Listener.Addr().String())
	resolver, err := newResolverWithTLS(proxyURL, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig)
	require.NoError(t, err)
	texts, err := resolver.LookupTXT(context.Background(), "features.example")
	require.NoError(t, err)
	assert.Equal(t, []string{"unquoted", `"quoted text"`}, texts)
}
