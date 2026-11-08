package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"
)

const (
	maxDNSMessageSize    = 65535
	maxConcurrentQueries = 64
	maxUDPMessageSize    = 65507
)

// Exchanger sends a wire-format DNS query to a DNS-over-HTTPS service.
type Exchanger interface {
	Exchange(ctx context.Context, message []byte) ([]byte, error)
}

// Server forwards UDP DNS messages to exchanger and returns its DoH responses.
type Server struct {
	conn      *net.UDPConn
	exchanger Exchanger
	log       *zerolog.Logger
}

// Listen binds a UDP DNS proxy to a loopback IP and port. Port zero selects an ephemeral port.
func Listen(ip net.IP, port int, exchanger Exchanger, log *zerolog.Logger) (*Server, error) {
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("DNS proxy must bind to a loopback IP address")
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("DNS proxy port is invalid")
	}
	if exchanger == nil {
		return nil, fmt.Errorf("DNS proxy requires a DoH exchanger")
	}
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen for UDP DNS queries: %w", err)
	}
	return &Server{conn: conn, exchanger: exchanger, log: log}, nil
}

// Addr returns the server's local UDP address.
func (s *Server) Addr() *net.UDPAddr {
	addr, _ := s.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

// Close stops the UDP listener.
func (s *Server) Close() error {
	return s.conn.Close()
}

// Serve forwards incoming DNS packets until ctx is canceled or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = s.conn.Close()
	})
	defer stopCancellation()

	var requests sync.WaitGroup
	defer requests.Wait()
	concurrent := make(chan struct{}, maxConcurrentQueries)
	buffer := make([]byte, maxDNSMessageSize)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP DNS query: %w", err)
		}
		query := append([]byte(nil), buffer[:n]...)
		select {
		case concurrent <- struct{}{}:
		default:
			continue
		}
		requests.Add(1)
		go func(addr *net.UDPAddr, query []byte) {
			defer requests.Done()
			defer func() { <-concurrent }()
			response, err := s.exchanger.Exchange(ctx, query)
			if err != nil {
				s.log.Debug().Err(err).Msg("DoH DNS exchange failed")
				response = servfailResponse(query)
			} else if len(response) > maxUDPMessageSize {
				response = servfailResponse(query)
			}
			if len(response) == 0 {
				return
			}
			if _, err := s.conn.WriteToUDP(response, addr); err != nil {
				s.log.Debug().Err(err).Msg("Failed to send DNS proxy response")
			}
		}(addr, query)
	}
}

func servfailResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	response := append([]byte(nil), query...)
	response[2] = (response[2] & 0x79) | 0x80
	response[3] = (response[3] & 0x70) | 0x80 | 2
	for _, countOffset := range []int{6, 8, 10} {
		response[countOffset] = 0
		response[countOffset+1] = 0
	}
	return response
}
