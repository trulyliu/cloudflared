package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	resolveEndpoint   = "https://dns.google/resolve"
	requestTimeout    = 15 * time.Second
	maxResponseSize   = 1 << 20
	maxDNSMessageSize = 65535

	typeCNAME = 5
	typeA     = 1
	typeTXT   = 16
	typeAAAA  = 28
	typeSRV   = 33
)

// Resolver performs DNS-over-HTTPS requests through the configured HTTP proxy.
type Resolver struct {
	client       *http.Client
	endpoint     url.URL
	wireEndpoint url.URL
}

// NewResolver creates a resolver whose requests are sent only through proxyURL.
func NewResolver(proxyURL *url.URL) (*Resolver, error) {
	if proxyURL == nil || !strings.EqualFold(proxyURL.Scheme, "http") || proxyURL.Host == "" {
		return nil, fmt.Errorf("a valid HTTP proxy URL is required")
	}
	return newResolver(proxyURL, resolveEndpoint)
}

// NewDirectResolver creates a resolver that sends DoH requests without an HTTP proxy.
func NewDirectResolver() (*Resolver, error) {
	return newResolverWithTLS(nil, resolveEndpoint, nil)
}

func newResolver(proxyURL *url.URL, endpoint string) (*Resolver, error) {
	return newResolverWithTLS(proxyURL, endpoint, nil)
}

func newResolverWithTLS(proxyURL *url.URL, endpoint string, tlsConfig *tls.Config) (*Resolver, error) {
	if proxyURL != nil && (!strings.EqualFold(proxyURL.Scheme, "http") || proxyURL.Host == "") {
		return nil, fmt.Errorf("a valid HTTP proxy URL is required")
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil || endpointURL.Scheme != "https" || endpointURL.Host == "" {
		return nil, fmt.Errorf("invalid DoH endpoint")
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	wireEndpoint := *endpointURL
	wireEndpoint.Path = "/dns-query"
	wireEndpoint.RawPath = ""
	wireEndpoint.RawQuery = ""
	return &Resolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
		endpoint:     *endpointURL,
		wireEndpoint: wireEndpoint,
	}, nil
}

// Exchange sends a wire-format DNS message through the resolver's configured DoH transport.
func (r *Resolver) Exchange(ctx context.Context, message []byte) ([]byte, error) {
	if len(message) < 12 || message[2]&0x80 != 0 {
		return nil, fmt.Errorf("invalid DNS query message")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.wireEndpoint.String(), bytes.NewReader(message))
	if err != nil {
		return nil, fmt.Errorf("create DoH exchange request: %w", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("DoH exchange failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH exchange returned HTTP status %d", response.StatusCode)
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH exchange response: %w", err)
	}
	if len(answer) < 12 || len(answer) > maxDNSMessageSize || answer[2]&0x80 == 0 || binary.BigEndian.Uint16(answer[:2]) != binary.BigEndian.Uint16(message[:2]) {
		return nil, fmt.Errorf("invalid DoH DNS response message")
	}
	return answer, nil
}

// LookupSRV resolves SRV records and preserves the answer order returned by DNS.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	queryName := "_" + service + "._" + proto + "." + name
	answers, err := r.lookup(ctx, queryName, typeSRV)
	if err != nil {
		return "", nil, err
	}
	records := make([]*net.SRV, 0, len(answers))
	for _, answer := range answers {
		if answer.Type == typeCNAME {
			continue
		}
		fields := strings.Fields(answer.Data)
		if answer.Type != typeSRV || len(fields) != 4 {
			return "", nil, fmt.Errorf("malformed SRV answer for %q", queryName)
		}
		priority, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("malformed SRV priority for %q", queryName)
		}
		weight, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("malformed SRV weight for %q", queryName)
		}
		port, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("malformed SRV port for %q", queryName)
		}
		target := strings.TrimSuffix(fields[3], ".")
		if target == "" || net.ParseIP(target) != nil {
			return "", nil, fmt.Errorf("malformed SRV target for %q", queryName)
		}
		records = append(records, &net.SRV{Priority: uint16(priority), Weight: uint16(weight), Port: uint16(port), Target: target + "."})
	}
	return queryName, records, nil
}

// LookupIP returns A and AAAA records. One successful query is sufficient.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	var errs []error
	for _, recordType := range []int{typeA, typeAAAA} {
		answers, err := r.lookup(ctx, host, recordType)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, answer := range answers {
			if answer.Type == typeCNAME {
				continue
			}
			if answer.Type != recordType {
				return nil, fmt.Errorf("malformed address answer for %q", host)
			}
			ip := net.ParseIP(answer.Data)
			if ip == nil || (recordType == typeA && ip.To4() == nil) || (recordType == typeAAAA && (ip.To4() != nil || ip.To16() == nil)) {
				return nil, fmt.Errorf("malformed address answer for %q", host)
			}
			ips = append(ips, ip)
		}
	}
	if len(errs) == 2 {
		return nil, fmt.Errorf("a and AAAA lookups for %q failed: %w", host, errors.Join(errs...))
	}
	return ips, nil
}

// LookupTXT resolves TXT records and returns their decoded strings.
func (r *Resolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	answers, err := r.lookup(ctx, host, typeTXT)
	if err != nil {
		return nil, err
	}
	records := make([]string, 0, len(answers))
	for _, answer := range answers {
		if answer.Type == typeCNAME {
			continue
		}
		if answer.Type != typeTXT {
			return nil, fmt.Errorf("malformed TXT answer for %q", host)
		}
		records = append(records, answer.Data)
	}
	return records, nil
}

type dnsAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dnsResponse struct {
	Status *int        `json:"Status"`
	Answer []dnsAnswer `json:"Answer"`
}

func (r *Resolver) lookup(ctx context.Context, name string, recordType int) ([]dnsAnswer, error) {
	endpoint := r.endpoint
	query := endpoint.Query()
	query.Set("name", name)
	query.Set("type", strconv.Itoa(recordType))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	request.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("DoH query for %q type %d failed: %w", name, recordType, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH query for %q type %d returned HTTP status %d", name, recordType, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("DoH response exceeds size limit")
	}
	var result dnsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode DoH response: %w", err)
	}
	if result.Status == nil {
		return nil, fmt.Errorf("DoH response is missing DNS status")
	}
	if *result.Status != 0 {
		return nil, fmt.Errorf("DNS query for %q type %d returned status %d", name, recordType, *result.Status)
	}
	return result.Answer, nil
}
