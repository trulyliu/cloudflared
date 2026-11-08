package main

import (
	"reflect"
	"testing"
)

func TestNormalizeDNSProxyArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "bare flag defaults to IPv4 loopback",
			args: []string{"cloudflared", "tunnel", "run", "--dns-proxy"},
			want: []string{"cloudflared", "tunnel", "run", "--dns-proxy=127.0.0.1"},
		},
		{
			name: "explicit loopback address is retained",
			args: []string{"cloudflared", "tunnel", "run", "--dns-proxy", "127.0.0.2"},
			want: []string{"cloudflared", "tunnel", "run", "--dns-proxy", "127.0.0.2"},
		},
		{
			name: "following tunnel name is not consumed as address",
			args: []string{"cloudflared", "tunnel", "run", "--dns-proxy", "my-tunnel"},
			want: []string{"cloudflared", "tunnel", "run", "--dns-proxy=127.0.0.1", "my-tunnel"},
		},
		{
			name: "end-of-options marker is respected",
			args: []string{"cloudflared", "--", "--dns-proxy"},
			want: []string{"cloudflared", "--", "--dns-proxy"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeDNSProxyArgs(test.args); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("normalizeDNSProxyArgs() = %v, want %v", got, test.want)
			}
		})
	}
}
