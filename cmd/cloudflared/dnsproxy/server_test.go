package dnsproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exchangeFunc func(context.Context, []byte) ([]byte, error)

func (f exchangeFunc) Exchange(ctx context.Context, message []byte) ([]byte, error) {
	return f(ctx, message)
}

func TestServerForwardsUDPQueriesToDoHExchanger(t *testing.T) {
	t.Parallel()

	query := testDNSQuery()
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	gotQuery := make(chan []byte, 1)
	logger := zerolog.Nop()
	server, err := Listen(net.ParseIP("127.0.0.1"), 0, exchangeFunc(func(_ context.Context, message []byte) ([]byte, error) {
		gotQuery <- append([]byte(nil), message...)
		return answer, nil
	}), &logger)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()

	client, err := net.DialUDP("udp", nil, server.Addr())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	_, err = client.Write(query)
	require.NoError(t, err)
	response := make([]byte, maxDNSMessageSize)
	n, err := client.Read(response)
	require.NoError(t, err)
	assert.Equal(t, answer, response[:n])
	assert.Equal(t, query, <-gotQuery)

	cancel()
	select {
	case err := <-serveErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("DNS proxy did not stop after context cancellation")
	}
}

func TestServerReturnsSERVFAILWhenDoHExchangeFails(t *testing.T) {
	t.Parallel()

	query := testDNSQuery()
	logger := zerolog.Nop()
	server, err := Listen(net.ParseIP("127.0.0.1"), 0, exchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("DoH unavailable")
	}), &logger)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	client, err := net.DialUDP("udp", nil, server.Addr())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	_, err = client.Write(query)
	require.NoError(t, err)
	response := make([]byte, maxDNSMessageSize)
	n, err := client.Read(response)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 12)
	response = response[:n]
	assert.Equal(t, query[:2], response[:2])
	assert.NotZero(t, response[2]&0x80)
	assert.Equal(t, byte(2), response[3]&0x0f)
	assert.Equal(t, uint16(0), uint16(response[6])<<8|uint16(response[7]))
	cancel()
	select {
	case err := <-serveErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("DNS proxy did not stop after context cancellation")
	}
}

func TestListenRejectsNonLoopbackAddress(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	_, err := Listen(net.ParseIP("192.0.2.1"), 0, exchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, nil
	}), &logger)
	require.Error(t, err)
}

func testDNSQuery() []byte {
	return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
}
