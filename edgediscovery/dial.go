package edgediscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// DialEdge makes a TLS connection to a Cloudflare edge node
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	// Inherit from parent context so we can cancel (Ctrl-C) while dialing
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	dialer := net.Dialer{}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}
	edgeConn, err := dialer.DialContext(dialCtx, "tcp", edgeTCPAddr.String())
	if err != nil {
		return nil, newDialError(err, "DialContext error")
	}

	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	if err := tlsEdgeConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = tlsEdgeConn.Close()
		return nil, newDialError(err, "set TLS edge deadline error")
	}
	if err = tlsEdgeConn.Handshake(); err != nil {
		_ = tlsEdgeConn.Close()
		return nil, newDialError(err, "TLS handshake with edge error")
	}
	// clear the deadline on the conn; http2 has its own timeouts
	if err := tlsEdgeConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsEdgeConn.Close()
		return nil, newDialError(err, "clear TLS edge deadline error")
	}
	return tlsEdgeConn, nil
}

// DialEdgeViaProxy establishes an HTTP CONNECT tunnel to an edge address and completes TLS over it.
func DialEdgeViaProxy(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
	proxyURL *url.URL,
) (net.Conn, error) {
	if proxyURL == nil || !strings.EqualFold(proxyURL.Scheme, "http") || proxyURL.Host == "" {
		return nil, newDialError(fmt.Errorf("a valid HTTP proxy is required"), "proxy configuration error")
	}
	if edgeTCPAddr == nil || edgeTCPAddr.IP.To16() == nil || edgeTCPAddr.Port < 1 || edgeTCPAddr.Port > 65535 {
		return nil, newDialError(fmt.Errorf("invalid edge TCP address"), "proxy CONNECT target error")
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()
	dialer := net.Dialer{}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}
	proxyConn, err := dialer.DialContext(dialCtx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, newDialError(err, "dial proxy error")
	}
	connected := false
	defer func() {
		if !connected {
			_ = proxyConn.Close()
		}
	}()
	deadline, ok := dialCtx.Deadline()
	if !ok {
		return nil, newDialError(fmt.Errorf("proxy dial has no deadline"), "proxy connection error")
	}
	if err := proxyConn.SetDeadline(deadline); err != nil {
		return nil, newDialError(err, "set proxy connection deadline error")
	}
	stopCancellation := context.AfterFunc(dialCtx, func() {
		_ = proxyConn.SetDeadline(time.Now())
	})
	defer stopCancellation()

	destination := net.JoinHostPort(edgeTCPAddr.IP.String(), strconv.Itoa(edgeTCPAddr.Port))
	if _, err := fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", destination, destination); err != nil {
		return nil, newDialError(err, "write proxy CONNECT request error")
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		proxyAuthorization := base64.StdEncoding.EncodeToString([]byte(credentials))
		if _, err := fmt.Fprintf(proxyConn, "Proxy-Authorization: Basic %s\r\n", proxyAuthorization); err != nil {
			return nil, newDialError(err, "write proxy authentication error")
		}
	}
	if _, err := fmt.Fprint(proxyConn, "\r\n"); err != nil {
		return nil, newDialError(err, "finish proxy CONNECT request error")
	}
	reader := bufio.NewReader(proxyConn)
	//nolint:bodyclose // On 200 CONNECT, the response body is the tunnel and must stay open for TLS.
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, newDialError(fmt.Errorf("invalid proxy CONNECT response"), "read proxy CONNECT response error")
	}
	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, newDialError(fmt.Errorf("proxy CONNECT returned HTTP status %d", response.StatusCode), "proxy CONNECT error")
	}

	tlsConn := tls.Client(&bufferedConn{Conn: proxyConn, reader: reader}, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, newDialError(err, "TLS handshake with edge through proxy error")
	}
	if !stopCancellation() || dialCtx.Err() != nil {
		if err := dialCtx.Err(); err != nil {
			return nil, newDialError(err, "edge dial canceled")
		}
	}
	if err := proxyConn.SetDeadline(time.Time{}); err != nil {
		return nil, newDialError(err, "clear proxy connection deadline error")
	}
	connected = true
	return tlsConn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// DialError is an error returned from DialEdge
type DialError struct {
	cause error
}

func newDialError(err error, message string) error {
	return DialError{cause: errors.Wrap(err, message)}
}

func (e DialError) Error() string {
	return e.cause.Error()
}

func (e DialError) Cause() error {
	return e.cause
}
