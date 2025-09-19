package filter

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// Serve53 starts a DNS proxy that enforces an allowlist by QNAME.
func Serve53(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":53"
	}

	handler := createDNSHandler(allowlist, opts)
	udpSrv, tcpSrv := setupDNSServers(opts.ListenAddr, handler)

	return runDNSServers(ctx, udpSrv, tcpSrv, opts)
}

// createDNSHandler creates and configures the DNS handler.
func createDNSHandler(allowlist []string, opts Options) *dnsHandler {
	upstreams := defaultUpstreamsFromEnv()

	return &dnsHandler{
		allowlist: allowlist,
		opts:      opts,
		upstreams: upstreams,
		timeout:   durOrDefault(time.Duration(opts.DialTimeout)*time.Millisecond, 3*time.Second),
	}
}

// setupDNSServers creates UDP and TCP DNS servers.
func setupDNSServers(listenAddr string, handler *dnsHandler) (*dns.Server, *dns.Server) {
	dns.HandleFunc(".", handler.handle)

	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}

	return udpSrv, tcpSrv
}

// runDNSServers starts the DNS servers and handles shutdown.
func runDNSServers(ctx context.Context, udpSrv, tcpSrv *dns.Server, opts Options) error {
	if opts.Logger != nil {
		upstreams := defaultUpstreamsFromEnv()
		opts.Logger.Info("dns.listen",
			"udp", opts.ListenAddr,
			"tcp", opts.ListenAddr,
			"upstreams", upstreams,
		)
	}

	errCh := make(chan error, 2)

	// Start servers
	startUDPServer(udpSrv, errCh, opts)
	startTCPServer(tcpSrv, errCh, opts)

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		_ = udpSrv.ShutdownContext(ctx)
		_ = tcpSrv.ShutdownContext(ctx)
	}()

	// Wait for completion
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// startUDPServer starts the UDP DNS server.
func startUDPServer(udpSrv *dns.Server, errCh chan error, opts Options) {
	go func() {
		err := udpSrv.ListenAndServe()
		if err != nil {
			if opts.Logger != nil {
				opts.Logger.Error("dns.listen_udp_error", "addr", opts.ListenAddr, "err", err.Error())
			}

			errCh <- err
		}
	}()
}

// startTCPServer starts the TCP DNS server.
func startTCPServer(tcpSrv *dns.Server, errCh chan error, opts Options) {
	go func() {
		err := tcpSrv.ListenAndServe()
		if err != nil {
			if opts.Logger != nil {
				opts.Logger.Error("dns.listen_tcp_error", "addr", opts.ListenAddr, "err", err.Error())
			}

			errCh <- err
		}
	}()
}

type dnsHandler struct {
	allowlist []string
	opts      Options
	upstreams []string
	timeout   time.Duration
}

//nolint:cyclop,gocognit,funlen
func (handler *dnsHandler) handle(writer dns.ResponseWriter, request *dns.Msg) {
	lg := handler.opts.Logger

	remoteAddr := ""
	remotePort := 0

	if writer != nil && writer.RemoteAddr() != nil {
		remote := writer.RemoteAddr().String()

		host, port, err := net.SplitHostPort(remote)
		if err == nil {
			remoteAddr = host

			p, parseErr := strconv.Atoi(port)
			if parseErr == nil {
				remotePort = p
			}
		} else {
			remoteAddr = remote
		}
	}

	// Emit an early synthetic REDIRECTED for the incoming query to help correlate
	// with kernel NFLOG entries and suppress duplicates. Use the listener/local
	// address (proxy dst) when available, otherwise fall back to the first
	// configured upstream (commonly 127.0.0.11:53).
	flowID := ""

	if lg != nil {
		dst := ""
		if writer != nil && writer.LocalAddr() != nil {
			dst = writer.LocalAddr().String()
		}

		if dst == "" && len(handler.upstreams) > 0 {
			dst = handler.upstreams[0]
		}

		if dst != "" {
			flowID = EmitSyntheticUDP(lg, "dns", remoteAddr, remotePort, dst)
		}
	}

	if len(request.Question) == 0 {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Rcode = dns.RcodeFormatError
		_ = writer.WriteMsg(message)

		return
	}

	question := request.Question[0]
	qname := strings.TrimSuffix(question.Name, ".") // policy uses normalizeDomain internally
	qtype := question.Qtype

	enforce := (qtype == dns.TypeA || qtype == dns.TypeAAAA)
	allowed := allowedHost(qname, handler.allowlist)

	// Enforced types blocked -> sinkhole
	if enforce && !allowed {
		if lg != nil {
			lg.Info("dns.blocked",
				"time", time.Now().UTC().Format(time.RFC3339Nano),
				"component", "dns",
				"action", "BLOCKED",
				"qname", qname,
				"qtype", typeString(qtype),
				"source_ip", remoteAddr,
				"source_port", remotePort,
				"flow_id", flowID,
				"note", "sinkhole",
			)
		}

		message := new(dns.Msg)
		message.SetReply(request)

		switch qtype {
		case dns.TypeA:
			message.Answer = append(message.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   net.IPv4(0, 0, 0, 0),
			})
		case dns.TypeAAAA:
			message.Answer = append(message.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
				AAAA: net.IPv6zero,
			})
		default:
			message.Rcode = dns.RcodeNameError
		}

		_ = writer.WriteMsg(message)

		return
	}

	// Non-enforced types blocked -> NXDOMAIN
	if !enforce && !allowed {
		if lg != nil {
			lg.Info("dns.blocked",
				"time", time.Now().UTC().Format(time.RFC3339Nano),
				"component", "dns",
				"action", "BLOCKED",
				"qname", qname,
				"qtype", typeString(qtype),
				"source_ip", remoteAddr,
				"source_port", remotePort,
				"note", "nxdomain",
				"flow_id", flowID,
			)
		}

		message := new(dns.Msg)
		message.SetReply(request)
		message.Rcode = dns.RcodeNameError
		_ = writer.WriteMsg(message)

		return
	}

	// Allowed -> forward to upstreams
	resp, _, err := handler.forward(request)
	if err != nil {
		// SERVFAIL on upstream error
		if lg != nil {
			lg.Warn("dns.upstream_error",
				"component", "dns",
				"action", "ERROR",
				"qname", qname,
				"qtype", typeString(qtype),
				"err", err.Error(),
				"source_ip", remoteAddr,
				"source_port", remotePort,
			)
		}

		message := new(dns.Msg)
		message.SetReply(request)
		message.Rcode = dns.RcodeServerFailure
		_ = writer.WriteMsg(message)

		return
	}

	if lg != nil {
		// Log ALLOWED at Info so it's visible under normal operation and include flow_id when available
		lg.Info("dns.allowed",
			"time", time.Now().UTC().Format(time.RFC3339Nano),
			"component", "dns",
			"action", "ALLOWED",
			"qname", qname,
			"qtype", typeString(qtype),
			"rcode", rcodeString(resp.Rcode),
			"source_ip", remoteAddr,
			"source_port", remotePort,
			"flow_id", flowID,
		)
	}

	_ = writer.WriteMsg(resp)
}

func (handler *dnsHandler) forward(request *dns.Msg) (*dns.Msg, string, error) {
	// UDP first, then TCP on truncation/need
	udpClient := &dns.Client{
		Net:     "udp",
		Timeout: handler.timeout,
		Dialer:  handler.markedDialer(), // SO_MARK=0x1 to bypass nft REDIRECT
	}
	tcpClient := &dns.Client{
		Net:     "tcp",
		Timeout: handler.timeout,
		Dialer:  handler.markedDialer(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), handler.timeout)
	defer cancel()

	for _, up := range handler.upstreams {
		// UDP attempt
		in, _, err := udpClient.ExchangeContext(ctx, request, up)
		if err == nil && in != nil {
			if in.Truncated {
				// Retry via TCP
				inTCP, _, err2 := tcpClient.ExchangeContext(ctx, request, up)
				if err2 == nil && inTCP != nil {
					return inTCP, up, nil
				}
				// try next upstream on TCP fail
			} else {
				return in, up, nil
			}
		}
		// try next upstream
	}

	return nil, "", os.ErrDeadlineExceeded
}

func (handler *dnsHandler) markedDialer() *net.Dialer {
	// build the Dialer explicitly rather than using a partial composite literal
	// to avoid exhaustruct warnings across Go versions while preserving fields.
	dialer := new(net.Dialer)
	dialer.Timeout = handler.timeout
	dialer.Control = func(_ string, _ string, c syscall.RawConn) error {
		var serr error

		err := c.Control(func(fd uintptr) {
			// Set SO_MARK=0x1 (match your nftables bypass rule)
			e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, socketMarkValue)
			if e != nil {
				serr = e
			}
		})
		if err != nil {
			return fmt.Errorf("control func error: %w", err)
		}

		return serr
	}

	return dialer
}

func durOrDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}

	return d
}

func defaultUpstreamsFromEnv() []string {
	// If you want to override, set DNS_UPSTREAMS="8.8.8.8:53,1.1.1.1:53"
	if v := strings.TrimSpace(os.Getenv("DNS_UPSTREAMS")); v != "" {
		parts := strings.Split(v, ",")

		out := make([]string, 0, len(parts))

		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}

		if len(out) > 0 {
			return out
		}
	}
	// Default to Docker's embedded resolver inside the container namespace
	return []string{"127.0.0.11:53"}
}

func typeString(dnsType uint16) string {
	switch dnsType {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeMX:
		return "MX"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeNS:
		return "NS"
	case dns.TypeSRV:
		return "SRV"
	default:
		return "TYPE" + dns.TypeToString[dnsType]
	}
}

func rcodeString(rc int) string {
	switch rc {
	case dns.RcodeSuccess:
		return "NOERROR"
	case dns.RcodeFormatError:
		return "FORMERR"
	case dns.RcodeServerFailure:
		return "SERVFAIL"
	case dns.RcodeNameError:
		return "NXDOMAIN"
	case dns.RcodeNotImplemented:
		return "NOTIMP"
	case dns.RcodeRefused:
		return "REFUSED"
	default:
		return "RCODE" + dns.RcodeToString[rc]
	}
}
