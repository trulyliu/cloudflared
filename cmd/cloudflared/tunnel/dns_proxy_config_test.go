package tunnel

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDNSProxyIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
		address string
		want    net.IP
		wantErr bool
	}{
		{name: "disabled ignores address", address: "not-an-ip"},
		{name: "default loopback", enabled: true, want: net.ParseIP("127.0.0.1")},
		{name: "custom IPv4 loopback", enabled: true, address: "127.0.0.2", want: net.ParseIP("127.0.0.2")},
		{name: "IPv6 loopback", enabled: true, address: "[::1]", want: net.ParseIP("::1")},
		{name: "reject non-loopback IP", enabled: true, address: "192.0.2.1", wantErr: true},
		{name: "reject hostname", enabled: true, address: "localhost", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDNSProxyIP(test.enabled, test.address)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}
