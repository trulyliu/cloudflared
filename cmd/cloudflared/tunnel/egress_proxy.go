package tunnel

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	sandEgressEnabledEnv = "SAND_EGRESS_TUNNEL_ENABLED"
	sandEgressProxyEnv   = "SAND_EGRESS_TUNNEL_PROXY_ADDR"
)

// sandEgressProxyFromEnv returns the configured HTTP proxy only when SAND egress is enabled.
// Errors intentionally omit the raw environment value, which may contain credentials.
func sandEgressProxyFromEnv(getenv func(string) string) (enabled bool, proxyURL *url.URL, err error) {
	if getenv(sandEgressEnabledEnv) != "1" {
		return false, nil, nil
	}
	proxyURL, err = parseSandEgressProxy(getenv(sandEgressProxyEnv))
	if err != nil {
		return true, nil, err
	}
	if proxyURL == nil {
		return true, nil, fmt.Errorf("%s must be set when %s=1", sandEgressProxyEnv, sandEgressEnabledEnv)
	}
	return true, proxyURL, nil
}

func sandEgressProxyURLFromEnv(getenv func(string) string) (*url.URL, error) {
	return parseSandEgressProxy(getenv(sandEgressProxyEnv))
}

func parseSandEgressProxy(proxyValue string) (*url.URL, error) {
	proxyValue = strings.TrimSpace(proxyValue)
	if proxyValue == "" {
		return nil, nil
	}
	value := proxyValue
	if !strings.Contains(value, "://") {
		if _, _, err := net.SplitHostPort(value); err != nil {
			return nil, fmt.Errorf("%s must be a host:port or HTTP proxy URL", sandEgressProxyEnv)
		}
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(value, "#") {
		return nil, fmt.Errorf("%s must be a valid HTTP proxy URL without a path, query, or fragment", sandEgressProxyEnv)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%s must include a proxy host", sandEgressProxyEnv)
	}
	port := parsed.Port()
	if port == "" {
		if strings.HasSuffix(parsed.Host, ":") {
			return nil, fmt.Errorf("%s contains an invalid proxy port", sandEgressProxyEnv)
		}
		if !strings.Contains(proxyValue, "://") {
			return nil, fmt.Errorf("%s must include a proxy port", sandEgressProxyEnv)
		}
		port = "80"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, fmt.Errorf("%s contains an invalid proxy port", sandEgressProxyEnv)
	}
	parsed.Host = net.JoinHostPort(host, strconv.FormatUint(portNumber, 10))
	return parsed, nil
}
