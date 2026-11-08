package tunnel

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cloudflare/cloudflared/connection"
)

func TestEffectiveTunnelProtocolForSandEgress(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	selector, err := connection.NewProtocolSelector(effectiveTunnelProtocol("quic", true), &logger)
	require.NoError(t, err)
	require.Equal(t, connection.HTTP2, selector.Current())
	_, hasFallback := selector.Fallback()
	require.False(t, hasFallback)

	legacySelector, err := connection.NewProtocolSelector(effectiveTunnelProtocol("quic", false), &logger)
	require.NoError(t, err)
	require.Equal(t, connection.QUIC, legacySelector.Current())
}
