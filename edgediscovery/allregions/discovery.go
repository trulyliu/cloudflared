package allregions

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/cloudflare/cloudflared/management"
)

const (
	// Used to discover HA origintunneld servers
	srvService = "v2-origintunneld"
	srvProto   = "tcp"
	srvName    = "argotunnel.com"

	// Used to fallback to DoT when we can't use the default resolver to
	// discover HA origintunneld servers (GitHub issue #75).
	dotServerName = "cloudflare-dns.com"
	dotServerAddr = "1.1.1.1:853"
	dotTimeout    = 15 * time.Second

	logFieldAddress = "address"
)

// Redeclare network functions so they can be overridden in tests.
var (
	netLookupSRV = net.LookupSRV
	netLookupIP  = net.LookupIP
)

// DNSResolver provides the DNS lookups required for edge discovery.
type DNSResolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// ContextualResolver binds resolver lookups to ctx for discovery APIs without a context parameter.
func ContextualResolver(ctx context.Context, resolver DNSResolver) DNSResolver {
	return contextBoundResolver{ctx: ctx, resolver: resolver}
}

type contextBoundResolver struct {
	ctx      context.Context
	resolver DNSResolver
}

func (r contextBoundResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return r.resolver.LookupSRV(r.ctx, service, proto, name)
}

func (r contextBoundResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	return r.resolver.LookupIP(r.ctx, host)
}

// ConfigIPVersion is the selection of IP versions from config
type ConfigIPVersion int8

const (
	Auto     ConfigIPVersion = 2
	IPv4Only ConfigIPVersion = 4
	IPv6Only ConfigIPVersion = 6
)

func (c ConfigIPVersion) String() string {
	switch c {
	case Auto:
		return "auto"
	case IPv4Only:
		return "4"
	case IPv6Only:
		return "6"
	default:
		return ""
	}
}

// IPVersion is the IP version of an EdgeAddr
type EdgeIPVersion int8

const (
	V4 EdgeIPVersion = 4
	V6 EdgeIPVersion = 6
)

// String returns the enum's constant name.
func (c EdgeIPVersion) String() string {
	switch c {
	case V4:
		return "4"
	case V6:
		return "6"
	default:
		return ""
	}
}

// EdgeAddr is a representation of possible ways to refer an edge location.
type EdgeAddr struct {
	TCP       *net.TCPAddr
	UDP       *net.UDPAddr
	IPVersion EdgeIPVersion
}

// If the call to net.LookupSRV fails, try to fall back to DoT from Cloudflare directly.
//
// Note: Instead of DoT, we could also have used DoH. Either of these:
//   - directly via the JSON API (https://1.1.1.1/dns-query?ct=application/dns-json&name=_origintunneld._tcp.argotunnel.com&type=srv)
//   - indirectly via `tunneldns.NewUpstreamHTTPS()`
//
// But both of these cases miss out on a key feature from the stdlib:
//
//	"The returned records are sorted by priority and randomized by weight within a priority."
//	(https://golang.org/pkg/net/#Resolver.LookupSRV)
//
// Does this matter? I don't know. It may someday. Let's use DoT so we don't need to worry about it.
// See also: Go feature request for stdlib-supported DoH: https://github.com/golang/go/issues/27552
var fallbackLookupSRV = lookupSRVWithDOT

var friendlyDNSErrorLines = []string{
	`Please try the following things to diagnose this issue:`,
	`  1. ensure that argotunnel.com is returning "origintunneld" service records.`,
	`     Run your system's equivalent of: dig srv _origintunneld._tcp.argotunnel.com`,
	`  2. ensure that your DNS resolver is not returning compressed SRV records.`,
	`     See GitHub issue https://github.com/golang/go/issues/27546`,
	`     For example, you could use Cloudflare's 1.1.1.1 as your resolver:`,
	`     https://developers.cloudflare.com/1.1.1.1/setting-up-1.1.1.1/`,
}

// EdgeDiscovery implements HA service discovery lookup.
func EdgeDiscovery(log *zerolog.Logger, srvService string) ([][]*EdgeAddr, error) {
	logger := log.With().Int(management.EventTypeKey, int(management.Cloudflared)).Logger()
	logger.Debug().
		Int(management.EventTypeKey, int(management.Cloudflared)).
		Str("domain", "_"+srvService+"._"+srvProto+"."+srvName).
		Msg("edge discovery: looking up edge SRV record")

	_, addrs, err := netLookupSRV(srvService, srvProto, srvName)
	if err != nil {
		_, fallbackAddrs, fallbackErr := fallbackLookupSRV(srvService, srvProto, srvName)
		if fallbackErr != nil || len(fallbackAddrs) == 0 {
			// use the original DNS error `err` in messages, not `fallbackErr`
			logger.Err(err).Msg("edge discovery: error looking up Cloudflare edge IPs: the DNS query failed")
			for _, s := range friendlyDNSErrorLines {
				logger.Error().Msg(s)
			}
			return nil, errors.Wrapf(err, "Could not lookup srv records on _%v._%v.%v", srvService, srvProto, srvName)
		}
		// Accept the fallback results and keep going
		addrs = fallbackAddrs
	}

	var resolvedAddrPerCNAME [][]*EdgeAddr
	for _, addr := range addrs {
		edgeAddrs, err := resolveSRV(addr)
		if err != nil {
			return nil, err
		}
		logAddrs := make([]string, len(edgeAddrs))
		for i, e := range edgeAddrs {
			logAddrs[i] = e.UDP.IP.String()
		}
		logger.Debug().
			Strs("addresses", logAddrs).
			Msg("edge discovery: resolved edge addresses")
		resolvedAddrPerCNAME = append(resolvedAddrPerCNAME, edgeAddrs)
	}

	return resolvedAddrPerCNAME, nil
}

// EdgeDiscoveryWithResolver discovers edge addresses using only the supplied resolver.
// Unlike EdgeDiscovery, it never falls back to the system resolver or DoT.
func EdgeDiscoveryWithResolver(log *zerolog.Logger, srvService string, resolver DNSResolver) ([][]*EdgeAddr, error) {
	if resolver == nil {
		return nil, fmt.Errorf("edge discovery requires an injected DNS resolver")
	}
	logger := log.With().Int(management.EventTypeKey, int(management.Cloudflared)).Logger()
	logger.Debug().
		Int(management.EventTypeKey, int(management.Cloudflared)).
		Str("domain", "_"+srvService+"._"+srvProto+"."+srvName).
		Msg("edge discovery: looking up edge SRV record")

	_, addrs, err := resolver.LookupSRV(context.Background(), srvService, srvProto, srvName)
	if err != nil {
		logger.Err(err).Msg("edge discovery: injected DNS resolver failed to look up Cloudflare edge SRV records")
		return nil, errors.Wrap(err, "failed to look up Cloudflare edge SRV records")
	}

	resolvedAddrPerCNAME := make([][]*EdgeAddr, 0, len(addrs))
	for _, addr := range addrs {
		edgeAddrs, err := resolveSRVWithResolver(context.Background(), resolver, addr)
		if err != nil {
			return nil, err
		}
		logAddrs := make([]string, len(edgeAddrs))
		for i, edgeAddr := range edgeAddrs {
			logAddrs[i] = edgeAddr.UDP.IP.String()
		}
		logger.Debug().Strs("addresses", logAddrs).Msg("edge discovery: resolved edge addresses")
		resolvedAddrPerCNAME = append(resolvedAddrPerCNAME, edgeAddrs)
	}
	return resolvedAddrPerCNAME, nil
}

func resolveSRVWithResolver(ctx context.Context, resolver DNSResolver, srv *net.SRV) ([]*EdgeAddr, error) {
	if srv == nil || srv.Target == "" {
		return nil, fmt.Errorf("edge SRV record has no target")
	}
	ips, err := resolver.LookupIP(ctx, srv.Target)
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve IP addresses for an edge SRV target")
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("edge SRV target resolved to no IP addresses")
	}
	addrs := make([]*EdgeAddr, len(ips))
	for i, ip := range ips {
		if ip == nil {
			return nil, fmt.Errorf("edge SRV target returned an invalid IP address")
		}
		version := V6
		if ip.To4() != nil {
			version = V4
		}
		addrs[i] = &EdgeAddr{
			TCP:       &net.TCPAddr{IP: ip, Port: int(srv.Port)},
			UDP:       &net.UDPAddr{IP: ip, Port: int(srv.Port)},
			IPVersion: version,
		}
	}
	return addrs, nil
}

// ResolveAddrsWithResolver resolves custom edge addresses using the supplied resolver for hostnames.
// Literal IP addresses are parsed locally and do not trigger a DNS lookup.
func ResolveAddrsWithResolver(addrs []string, log *zerolog.Logger, resolver DNSResolver) (resolved []*EdgeAddr) {
	for _, addr := range addrs {
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to TCP address")
			continue
		}
		if host == "" {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(fmt.Errorf("address host is empty")).Msg("edge discovery: failed to resolve to TCP address")
			continue
		}
		port, err := net.LookupPort("tcp", portText)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to TCP address")
			continue
		}

		var ip net.IP
		var zone string
		if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex >= 0 {
			if scopedIP := net.ParseIP(host[:zoneIndex]); scopedIP != nil {
				ip = scopedIP
				zone = host[zoneIndex+1:]
			}
		}
		if ip == nil {
			ip = net.ParseIP(host)
		}
		if ip == nil {
			if resolver == nil {
				log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
					Str(logFieldAddress, addr).Msg("edge discovery: injected DNS resolver is required")
				continue
			}
			ips, err := resolver.LookupIP(context.Background(), host)
			if err != nil {
				log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
					Str(logFieldAddress, addr).Err(err).Msg("edge discovery: injected DNS resolver failed to resolve edge hostname")
				continue
			}
			if len(ips) == 0 || ips[0] == nil {
				log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
					Str(logFieldAddress, addr).Msg("edge discovery: injected DNS resolver returned no IP addresses for edge hostname")
				continue
			}
			ip = ips[0]
		}
		version := V6
		if ip.To4() != nil {
			version = V4
		}
		resolved = append(resolved, &EdgeAddr{
			TCP:       &net.TCPAddr{IP: ip, Port: port, Zone: zone},
			UDP:       &net.UDPAddr{IP: ip, Port: port, Zone: zone},
			IPVersion: version,
		})
	}
	return
}

func lookupSRVWithDOT(srvService string, srvProto string, srvName string) (cname string, addrs []*net.SRV, err error) {
	// Inspiration: https://github.com/artyom/dot/blob/master/dot.go
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", dotServerAddr)
			if err != nil {
				return nil, err
			}
			tlsConfig := &tls.Config{ServerName: dotServerName}
			return tls.Client(conn, tlsConfig), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), dotTimeout)
	defer cancel()
	return r.LookupSRV(ctx, srvService, srvProto, srvName)
}

func resolveSRV(srv *net.SRV) ([]*EdgeAddr, error) {
	ips, err := netLookupIP(srv.Target)
	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't resolve SRV record %v", srv)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("SRV record %v had no IPs", srv)
	}
	addrs := make([]*EdgeAddr, len(ips))
	for i, ip := range ips {
		version := V6
		if ip.To4() != nil {
			version = V4
		}
		addrs[i] = &EdgeAddr{
			TCP:       &net.TCPAddr{IP: ip, Port: int(srv.Port)},
			UDP:       &net.UDPAddr{IP: ip, Port: int(srv.Port)},
			IPVersion: version,
		}
	}
	return addrs, nil
}

// ResolveAddrs resolves TCP address given a list of addresses. Address can be a hostname, however, it will return at most one
// of the hostname's IP addresses.
func ResolveAddrs(addrs []string, log *zerolog.Logger) (resolved []*EdgeAddr) {
	for _, addr := range addrs {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to TCP address")
			continue
		}

		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to UDP address")
			continue
		}
		version := V6
		if udpAddr.IP.To4() != nil {
			version = V4
		}
		resolved = append(resolved, &EdgeAddr{
			TCP:       tcpAddr,
			UDP:       udpAddr,
			IPVersion: version,
		})
	}
	return
}
