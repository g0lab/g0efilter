package filter

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Serve53 starts a DNS proxy server that filters requests based on an allowlist of domains.
func Serve53(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":53"
	}

	handler := createDNSHandler(allowlist, opts)
	udpSrv, tcpSrv := setupDNSServers(opts.ListenAddr, handler)

	return runDNSServers(ctx, udpSrv, tcpSrv, opts)
}

// createDNSHandler creates a DNS handler with the given allowlist and options.
func createDNSHandler(allowlist []string, opts Options) *dnsHandler {
	upstreams := defaultUpstreamsFromEnv()

	return &dnsHandler{
		allowlist: allowlist,
		opts:      opts,
		upstreams: upstreams,
		timeout:   timeoutFromOptions(opts, 3*time.Second),
	}
}

// setupDNSServers creates UDP and TCP DNS servers using the provided listen address and handler.
func setupDNSServers(listenAddr string, handler *dnsHandler) (*dns.Server, *dns.Server) {
	dns.HandleFunc(".", handler.handle)

	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}

	return udpSrv, tcpSrv
}

// runDNSServers starts both UDP and TCP DNS servers and manages their lifecycle until context is done.
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

// startUDPServer starts the UDP DNS server in a goroutine and reports errors to the channel.
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

// startTCPServer starts the TCP DNS server in a goroutine and reports errors to the channel.
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

// handle processes incoming DNS requests and enforces the allowlist policy.
func (handler *dnsHandler) handle(writer dns.ResponseWriter, request *dns.Msg) {
	lg := handler.opts.Logger

	remoteAddr, remotePort := handler.parseRemoteAddr(writer)
	flowID := handler.emitSyntheticEvent(lg, writer, remoteAddr, remotePort)

	if len(request.Question) == 0 {
		handler.respondWithError(writer, request, dns.RcodeFormatError)

		return
	}

	question := request.Question[0]
	qname := strings.TrimSuffix(question.Name, ".")
	qtype := question.Qtype

	// Debug: Log DNS query details
	if lg != nil {
		lg.Debug("dns.query",
			"qname", qname,
			"qtype", typeString(qtype),
			"source_ip", remoteAddr,
			"source_port", remotePort,
		)
	}

	enforce := (qtype == dns.TypeA || qtype == dns.TypeAAAA)
	allowed := allowedHost(qname, handler.allowlist)

	if lg != nil {
		lg.Debug("dns.allowlist_check", "qname", qname, "qtype", typeString(qtype), "allowed", allowed, "enforce", enforce)
	}

	if enforce && !allowed {
		handler.handleBlockedEnforcedType(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)

		return
	}

	if !enforce && !allowed {
		handler.handleBlockedNonEnforcedType(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)

		return
	}

	handler.handleAllowedRequest(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)
}

// parseRemoteAddr extracts the IP address and port from the remote client.
func (handler *dnsHandler) parseRemoteAddr(writer dns.ResponseWriter) (string, int) {
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

	return remoteAddr, remotePort
}

// emitSyntheticEvent emits a synthetic nflog event for this DNS request and returns the flow ID.
func (handler *dnsHandler) emitSyntheticEvent(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	remoteAddr string,
	remotePort int,
) string {
	if lg == nil {
		return ""
	}

	dst := ""
	if writer != nil && writer.LocalAddr() != nil {
		dst = writer.LocalAddr().String()
	}

	if dst == "" && len(handler.upstreams) > 0 {
		dst = handler.upstreams[0]
	}

	if dst != "" {
		return EmitSyntheticUDP(lg, "dns", remoteAddr, remotePort, dst)
	}

	return ""
}

// respondWithError sends a DNS error response with the specified error code.
func (handler *dnsHandler) respondWithError(writer dns.ResponseWriter, request *dns.Msg, rcode int) {
	message := new(dns.Msg)
	message.SetReply(request)
	message.Rcode = rcode
	_ = writer.WriteMsg(message)
}

// handleBlockedEnforcedType handles blocked A/AAAA queries by responding with a sinkhole address.
func (handler *dnsHandler) handleBlockedEnforcedType(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) {
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
			"note", "sinkholed-not-allowlisted",
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
}

// handleBlockedNonEnforcedType handles blocked non-A/AAAA queries by responding with NXDOMAIN.
func (handler *dnsHandler) handleBlockedNonEnforcedType(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) {
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

	handler.respondWithError(writer, request, dns.RcodeNameError)
}

// handleAllowedRequest forwards allowed DNS queries to upstream servers and returns the response.
func (handler *dnsHandler) handleAllowedRequest(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) {
	resp, _, err := handler.forward(request)
	if err != nil {
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

		handler.respondWithError(writer, request, dns.RcodeServerFailure)

		return
	}

	if lg != nil {
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

// forward sends a DNS request to upstream servers, trying UDP first then TCP if truncated.
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
		if err != nil || in == nil {
			continue // try next upstream
		}

		if !in.Truncated {
			return in, up, nil
		}

		// Response truncated, retry via TCP
		if handler.opts.Logger != nil {
			handler.opts.Logger.Debug("dns.upstream_truncated", "upstream", up, "retrying_tcp", true)
		}

		inTCP, _, err2 := tcpClient.ExchangeContext(ctx, request, up)
		if err2 == nil && inTCP != nil {
			return inTCP, up, nil
		}
		// try next upstream on TCP fail
	}

	return nil, "", os.ErrDeadlineExceeded
}

// markedDialer creates a network dialer with SO_MARK set to bypass iptables rules.
func (handler *dnsHandler) markedDialer() *net.Dialer {
	return newMarkedDialer(handler.timeout)
}

// durOrDefault returns the duration if positive, otherwise returns the default value.
func durOrDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}

	return d
}

// defaultUpstreamsFromEnv reads DNS upstream servers from DNS_UPSTREAMS environment variable or returns default.
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

// typeString returns a human-readable string for a DNS query type.
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

// rcodeString returns a human-readable string for a DNS response code.
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
