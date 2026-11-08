package allregions

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (ea *EdgeAddr) String() string {
	return fmt.Sprintf("%s-%s", ea.TCP, ea.UDP)
}

func TestEdgeDiscovery(t *testing.T) {
	mockAddrs := newMockAddrs(19, 2, 5)
	netLookupSRV = mockNetLookupSRV(mockAddrs)
	netLookupIP = mockNetLookupIP(mockAddrs)

	expectedAddrSet := map[string]bool{}
	for _, addrs := range mockAddrs.addrMap {
		for _, addr := range addrs {
			expectedAddrSet[addr.String()] = true
		}
	}

	l := zerolog.Nop()
	addrLists, err := EdgeDiscovery(&l, "")
	require.NoError(t, err)
	actualAddrSet := map[string]bool{}
	for _, addrs := range addrLists {
		for _, addr := range addrs {
			actualAddrSet[addr.String()] = true
		}
	}

	assert.Equal(t, expectedAddrSet, actualAddrSet)
}

type injectedDNSResolver struct {
	srv       []*net.SRV
	lookupErr error
	ipResults map[string][]net.IP
	ipErrors  map[string]error
	srvCalls  int
	srvQuery  [3]string
	ipCalls   []string
}

func (r *injectedDNSResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r.srvCalls++
	r.srvQuery = [3]string{service, proto, name}
	if r.lookupErr != nil {
		return "", nil, r.lookupErr
	}
	return "", r.srv, nil
}

func (r *injectedDNSResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	r.ipCalls = append(r.ipCalls, host)
	return r.ipResults[host], r.ipErrors[host]
}

type resolverContextKey struct{}

type contextCaptureResolver struct {
	srvContextValue any
	ipContextValue  any
}

func (r *contextCaptureResolver) LookupSRV(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
	r.srvContextValue = ctx.Value(resolverContextKey{})
	return "", nil, nil
}

func (r *contextCaptureResolver) LookupIP(ctx context.Context, _ string) ([]net.IP, error) {
	r.ipContextValue = ctx.Value(resolverContextKey{})
	return nil, nil
}

func TestContextualResolverBindsLookupContext(t *testing.T) {
	t.Parallel()

	resolver := &contextCaptureResolver{}
	ctx := context.WithValue(context.Background(), resolverContextKey{}, "bound")
	contextual := ContextualResolver(ctx, resolver)
	_, _, err := contextual.LookupSRV(context.Background(), "service", "tcp", "example.com")
	require.NoError(t, err)
	_, err = contextual.LookupIP(context.Background(), "edge.example")
	require.NoError(t, err)
	assert.Equal(t, "bound", resolver.srvContextValue)
	assert.Equal(t, "bound", resolver.ipContextValue)
}

func TestEdgeDiscoveryWithResolverUsesResolverAndPreservesSRVOrder(t *testing.T) {
	oldLookupSRV, oldLookupIP, oldFallback := netLookupSRV, netLookupIP, fallbackLookupSRV
	netLookupSRV = func(string, string, string) (string, []*net.SRV, error) {
		t.Fatal("used system SRV resolver")
		return "", nil, nil
	}
	netLookupIP = func(string) ([]net.IP, error) {
		t.Fatal("used system IP resolver")
		return nil, nil
	}
	fallbackLookupSRV = func(string, string, string) (string, []*net.SRV, error) {
		t.Fatal("used DoT fallback")
		return "", nil, nil
	}
	defer func() { netLookupSRV, netLookupIP, fallbackLookupSRV = oldLookupSRV, oldLookupIP, oldFallback }()

	resolver := &injectedDNSResolver{
		srv: []*net.SRV{{Target: "first.example", Port: 7844}, {Target: "second.example", Port: 7844}},
		ipResults: map[string][]net.IP{
			"first.example":  {net.ParseIP("192.0.2.1")},
			"second.example": {net.ParseIP("192.0.2.2")},
		},
	}
	log := zerolog.Nop()
	got, err := EdgeDiscoveryWithResolver(&log, "service", resolver)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "192.0.2.1", got[0][0].TCP.IP.String())
	assert.Equal(t, "192.0.2.2", got[1][0].TCP.IP.String())
	assert.Equal(t, []string{"first.example", "second.example"}, resolver.ipCalls)
	assert.Equal(t, 1, resolver.srvCalls)
	assert.Equal(t, [3]string{"service", "tcp", "argotunnel.com"}, resolver.srvQuery)
}

func TestEdgeDiscoveryWithResolverDoesNotFallbackOnLookupFailure(t *testing.T) {
	oldLookupSRV, oldLookupIP, oldFallback := netLookupSRV, netLookupIP, fallbackLookupSRV
	var directCalls int
	netLookupSRV = func(string, string, string) (string, []*net.SRV, error) { directCalls++; return "", nil, nil }
	netLookupIP = func(string) ([]net.IP, error) { directCalls++; return nil, nil }
	fallbackLookupSRV = func(string, string, string) (string, []*net.SRV, error) { directCalls++; return "", nil, nil }
	defer func() { netLookupSRV, netLookupIP, fallbackLookupSRV = oldLookupSRV, oldLookupIP, oldFallback }()

	log := zerolog.Nop()
	resolver := &injectedDNSResolver{lookupErr: fmt.Errorf("injected SRV failure")}
	_, err := EdgeDiscoveryWithResolver(&log, "service", resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injected SRV failure")
	assert.Zero(t, directCalls)

	resolver = &injectedDNSResolver{
		srv:      []*net.SRV{{Target: "edge.example", Port: 7844}},
		ipErrors: map[string]error{"edge.example": fmt.Errorf("injected IP failure")},
	}
	_, err = EdgeDiscoveryWithResolver(&log, "service", resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "injected IP failure")
	assert.Zero(t, directCalls)
}

func TestResolveAddrsWithResolverUsesDoHForHostnamesAndNotLiterals(t *testing.T) {
	resolver := &injectedDNSResolver{ipResults: map[string][]net.IP{
		"edge.example": {net.ParseIP("192.0.2.20"), net.ParseIP("192.0.2.21")},
	}}
	log := zerolog.Nop()
	got := ResolveAddrsWithResolver([]string{"192.0.2.10:7844", "edge.example:7844"}, &log, resolver)
	require.Len(t, got, 2)
	assert.Equal(t, "192.0.2.10", got[0].TCP.IP.String())
	assert.Equal(t, "192.0.2.20", got[1].TCP.IP.String())
	assert.Equal(t, []string{"edge.example"}, resolver.ipCalls)
}
