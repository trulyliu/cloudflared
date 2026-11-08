package tunnel

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandEgressProxyFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		enabled    string
		proxy      string
		wantEnable bool
		wantURL    string
		wantErr    bool
	}{
		{name: "bare address", enabled: "1", proxy: "127.0.0.1:8791", wantEnable: true, wantURL: "http://127.0.0.1:8791"},
		{name: "authenticated URL", enabled: "1", proxy: "http://user:p%40ss@proxy.example:8080", wantEnable: true, wantURL: "http://user:p%40ss@proxy.example:8080"},            //nolint:gosec // Test fixture verifies authenticated URL parsing.
		{name: "authenticated URL defaults port", enabled: "1", proxy: "http://user:password@proxy.example", wantEnable: true, wantURL: "http://user:password@proxy.example:80"}, //nolint:gosec // Test fixture verifies default port handling with userinfo.
		{name: "missing proxy", enabled: "1", wantEnable: true, wantErr: true},
		{name: "malformed proxy", enabled: "1", proxy: "https://proxy.example:443", wantEnable: true, wantErr: true},
		{name: "invalid port", enabled: "1", proxy: "http://proxy.example:70000", wantEnable: true, wantErr: true},
		{name: "empty URL port", enabled: "1", proxy: "http://proxy.example:", wantEnable: true, wantErr: true},
		{name: "nonnumeric URL port", enabled: "1", proxy: "http://proxy.example:+80", wantEnable: true, wantErr: true},
		{name: "empty fragment", enabled: "1", proxy: "http://proxy.example:80#", wantEnable: true, wantErr: true},
		{name: "URL path", enabled: "1", proxy: "http://proxy.example:8080/path", wantEnable: true, wantErr: true},
		{name: "disabled ignores proxy", enabled: "true", proxy: "not a proxy", wantEnable: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(key string) string {
				switch key {
				case sandEgressEnabledEnv:
					return test.enabled
				case sandEgressProxyEnv:
					return test.proxy
				default:
					return ""
				}
			}
			enabled, proxyURL, err := sandEgressProxyFromEnv(getenv)
			assert.Equal(t, test.wantEnable, enabled)
			if test.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "password")
				return
			}
			require.NoError(t, err)
			if test.wantURL == "" {
				assert.Nil(t, proxyURL)
				return
			}
			expected, err := url.Parse(test.wantURL)
			require.NoError(t, err)
			assert.Equal(t, expected, proxyURL)
		})
	}
}

func TestSandEgressProxyURLFromEnvWithoutTunnelMode(t *testing.T) {
	t.Parallel()

	proxyURL, err := sandEgressProxyURLFromEnv(func(key string) string {
		if key == sandEgressProxyEnv {
			return "127.0.0.1:8791"
		}
		return ""
	})
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:8791", proxyURL.Host)
}

func TestSandEgressProxyURLFromEnvForDNSProxy(t *testing.T) {
	t.Parallel()

	proxyURL, err := sandEgressProxyURLFromEnv(func(key string) string {
		if key == sandEgressProxyEnv {
			return "127.0.0.1:8791"
		}
		return ""
	})
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	assert.Equal(t, "127.0.0.1:8791", proxyURL.Host)
}

func TestSandEgressProxyEnvironmentVariableIsSecret(t *testing.T) {
	t.Parallel()

	assert.True(t, isSecretEnvVar(sandEgressProxyEnv))
}
