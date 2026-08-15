package filter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g0lab/g0efilter/agent/netutil"
	"github.com/g0lab/g0efilter/agent/policy"
	"github.com/g0lab/g0efilter/agent/recovery"
	"github.com/g0lab/g0efilter/shared/actions"
	"github.com/miekg/dns"
)

const (
	dnsStartWait       = 2 * time.Second
	dnsShutdownTimeout = 5 * time.Second
)

var errDNSServerExited = errors.New("dns server exited unexpectedly")

// Serve53 starts a DNS proxy server that filters requests based on an allowlist of domains.
func Serve53(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":65053"
	}

	handler := createDNSHandler(NormalizePatterns(allowlist), opts)
	udpSrv, tcpSrv := setupDNSServers(opts.ListenAddr, handler)

	return runDNSServers(ctx, udpSrv, tcpSrv, handler.upstreams, opts)
}

func createDNSHandler(allowlist []string, opts Options) *dnsHandler {
	upstreams := defaultUpstreamsFromEnv()
	opts.Denylist = NormalizePatterns(opts.Denylist)
	opts.denyMatcher = newMatcher(opts.Denylist)

	var limiter *dnsRateLimiter
	if opts.DNSHardening {
		limiter = newDNSRateLimiter(opts.DNSRateQPS, opts.DNSRateBurst)
	}

	return &dnsHandler{
		allowlist: newMatcher(allowlist),
		ipAllow:   newIPAllowlist(opts.AllowIPs),
		opts:      opts,
		upstreams: upstreams,
		timeout:   timeoutFromOptions(opts, 3*time.Second),
		limiter:   limiter,
	}
}

func setupDNSServers(listenAddr string, handler *dnsHandler) (*dns.Server, *dns.Server) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler.handle)

	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp", Handler: mux}

	return udpSrv, tcpSrv
}

func runDNSServers(
	ctx context.Context,
	udpSrv, tcpSrv *dns.Server,
	upstreams []string,
	opts Options,
) error {
	if opts.Logger != nil {
		opts.Logger.Info("dns.listen",
			"udp", opts.ListenAddr,
			"tcp", opts.ListenAddr,
			"upstreams", upstreams,
		)
	}

	servers := []*dnsServer{newDNSServer(udpSrv, "udp"), newDNSServer(tcpSrv, "tcp")}

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		srv.serve(errCh, opts)
	}

	select {
	case <-ctx.Done():
		stopDNSServers(ctx, servers)

		return nil
	case serveErr := <-errCh:
		stopDNSServers(ctx, servers)

		return serveErr
	}
}

type dnsServer struct {
	srv     *dns.Server
	proto   string
	started chan struct{}
	done    chan struct{}
}

func newDNSServer(srv *dns.Server, proto string) *dnsServer {
	server := &dnsServer{
		srv:     srv,
		proto:   proto,
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}

	srv.NotifyStartedFunc = func() { close(server.started) }

	return server
}

func (s *dnsServer) serve(errCh chan<- error, opts Options) {
	go func() {
		defer close(s.done)

		err := recovery.Recovered(s.srv.ListenAndServe)
		if err == nil {
			err = fmt.Errorf("%w: %s", errDNSServerExited, s.proto)
		} else if opts.Logger != nil {
			opts.Logger.Error("dns.listen_"+s.proto+"_error", "addr", opts.ListenAddr, "err", err.Error())
		}

		errCh <- err
	}()
}

func (s *dnsServer) stop(ctx context.Context) {
	select {
	case <-s.done:
		return
	case <-s.started:
	case <-time.After(dnsStartWait):
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsShutdownTimeout)
	defer cancel()

	_ = s.srv.ShutdownContext(shutdownCtx)

	select {
	case <-s.done:
	case <-shutdownCtx.Done():
	}
}

func stopDNSServers(ctx context.Context, servers []*dnsServer) {
	var wg sync.WaitGroup

	for _, srv := range servers {
		wg.Go(func() { srv.stop(ctx) })
	}

	wg.Wait()
}

type dnsHandler struct {
	allowlist *hostMatcher
	ipAllow   *ipAllowlist
	opts      Options
	upstreams []string
	timeout   time.Duration
	limiter   *dnsRateLimiter
}

// ipAllowlist matches resolved IPs against the policy IP/CIDR allowlist.
type ipAllowlist struct {
	exact map[string]struct{}
	cidrs []*net.IPNet
}

func newIPAllowlist(entries []string) *ipAllowlist {
	m := &ipAllowlist{exact: make(map[string]struct{}, len(entries)), cidrs: nil}

	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}

		rule, err := policy.ParseIPPortRule(e)
		if err != nil {
			continue
		}

		_, ipnet, err := net.ParseCIDR(rule.Addr)
		if err == nil {
			m.cidrs = append(m.cidrs, ipnet)

			continue
		}

		if ip := net.ParseIP(rule.Addr); ip != nil {
			m.exact[ip.String()] = struct{}{}
		}
	}

	return m
}

func (m *ipAllowlist) len() int {
	return len(m.exact) + len(m.cidrs)
}

func (m *ipAllowlist) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if _, ok := m.exact[ip.String()]; ok {
		return true
	}

	for _, n := range m.cidrs {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// sanitizeAndLogQname validates and sanitizes the DNS query name. ok is false
// when a name was present but invalid; such queries must be refused, not policy-checked.
func (handler *dnsHandler) sanitizeAndLogQname(
	lg *slog.Logger,
	rawQname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
) (string, bool) {
	qname := strings.TrimSuffix(rawQname, ".")

	// Validate and sanitize DNS query name before using in logs
	sanitizedQname, valid := sanitizeDNSQname(qname)
	if !valid && qname != "" {
		if lg != nil {
			lg.Info("dns.qname_invalid",
				"raw_qname", qname,
				"qtype", typeString(qtype),
				"source_ip", remoteAddr,
				"source_port", remotePort,
			)
		}

		return "", false
	}

	if valid {
		qname = sanitizedQname
	}

	// Debug: Log DNS query details
	if lg != nil {
		lg.Debug("dns.query",
			"qname", qname,
			"qtype", typeString(qtype),
			"source_ip", remoteAddr,
			"source_port", remotePort,
		)
	}

	return qname, true
}

// handle processes incoming DNS requests and enforces the allowlist policy.
func (handler *dnsHandler) handle(writer dns.ResponseWriter, request *dns.Msg) {
	defer recovery.Guard(handler.opts.Logger, "dns")

	lg := handler.opts.Logger

	remoteAddr, remotePort := handler.parseRemoteAddr(writer)

	if handler.rateLimited(lg, writer, request, remoteAddr, remotePort) {
		return
	}

	flowID := handler.emitSyntheticEvent(lg, writer, remoteAddr, remotePort)

	if len(request.Question) == 0 {
		handler.respondWithError(writer, request, dns.RcodeFormatError)

		return
	}

	question := request.Question[0]
	qname, qnameOK := handler.sanitizeAndLogQname(lg, question.Name, question.Qtype, remoteAddr, remotePort)
	qtype := question.Qtype

	// Refused in every policy mode: an invalid name passed through as "" would
	// bypass the denylist and hardening checks under default-allow.
	if !qnameOK {
		handler.respondWithError(writer, request, dns.RcodeRefused)

		return
	}

	if handler.blockExfilQuery(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID) {
		return
	}

	enforce := (qtype == dns.TypeA || qtype == dns.TypeAAAA)
	permitted := hostPermittedBy(qname, handler.allowlist, handler.opts)

	if lg != nil {
		lg.Debug("dns.allowlist_check", "qname", qname, "qtype", typeString(qtype), "allowed", permitted, "enforce", enforce)
	}

	wasAudited := audited(permitted, handler.opts)

	if wasAudited {
		handler.logAuditedQuery(lg, qname, qtype, remoteAddr, remotePort, flowID)
	} else if !permitted {
		handler.handleNotPermitted(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)

		return
	}

	maybeLearnHostBy(qname, handler.allowlist, handler.opts)

	handler.handleAllowedRequest(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID, !wasAudited)
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

// rateLimited enforces the per-source query cap before any other work. It protects
// the proxy itself, so it applies even under audit/learning mode. Returns true when
// the request was refused.
func (handler *dnsHandler) rateLimited(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	remoteAddr string,
	remotePort int,
) bool {
	if handler.limiter == nil || handler.limiter.allow(remoteAddr) {
		return false
	}

	if lg != nil {
		lg.Warn("dns.rate_limited", "component", "dns", "source_ip", remoteAddr, "source_port", remotePort)
	}

	handler.respondWithError(writer, request, dns.RcodeRefused)

	return true
}

// blockExfilQuery applies the anti-exfil query checks. Returns true when the
// request was answered (REFUSED). Under audit/learning mode violations are
// logged but the query proceeds.
func (handler *dnsHandler) blockExfilQuery(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) bool {
	if !handler.opts.DNSHardening || qname == "" {
		return false
	}

	reason := checkExfilQuery(qname, qtype)
	if reason == "" {
		return false
	}

	enforce := !handler.opts.AuditMode && !handler.opts.LearningMode

	if lg != nil {
		action := "BLOCKED"
		if !enforce {
			action = "AUDIT"
		}

		fields := handler.dnsLogFields(action, qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "reason", reason, "note", "dns-hardening")
		lg.Warn("dns.hardening", fields...)
	}

	if !enforce {
		return false
	}

	handler.respondWithError(writer, request, dns.RcodeRefused)

	return true
}

// blockExfilResponse applies the anti-exfil answer checks. Returns true when the
// response was replaced with SERVFAIL.
func (handler *dnsHandler) blockExfilResponse(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	resp *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) bool {
	if !handler.opts.DNSHardening {
		return false
	}

	reason := checkExfilResponse(resp)
	if reason == "" {
		return false
	}

	enforce := !handler.opts.AuditMode && !handler.opts.LearningMode

	if lg != nil {
		action := "BLOCKED"
		if !enforce {
			action = "AUDIT"
		}

		fields := handler.dnsLogFields(action, qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "reason", reason, "note", "dns-hardening")
		lg.Warn("dns.hardening", fields...)
	}

	if !enforce {
		return false
	}

	handler.respondWithError(writer, request, dns.RcodeServerFailure)

	return true
}

// dnsLogFields builds the shared decision-log fields for DNS queries. BLOCKED
// records are flagged for alerting; ALLOWED/AUDIT records are not.
func (handler *dnsHandler) dnsLogFields(
	action, qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) []any {
	const fieldCap = 24

	fields := make([]any, 0, fieldCap)
	fields = append(fields,
		"component", "dns",
		"action", action,
		"qname", qname,
		"qtype", typeString(qtype),
		"source_ip", remoteAddr,
		"source_port", remotePort,
		"flow_id", flowID,
	)

	if action == actions.ActionBlocked {
		fields = append(fields, actions.KeyAlert, true)
	}

	return fields
}

// logAuditedQuery logs a would-be-blocked query that audit mode resolves anyway.
func (handler *dnsHandler) logAuditedQuery(
	lg *slog.Logger,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) {
	if lg == nil {
		return
	}

	fields := handler.dnsLogFields("AUDIT", qname, qtype, remoteAddr, remotePort, flowID)
	fields = append(fields, "note", "would-be-blocked")
	lg.Warn("dns.audit", fields...)
}

// handleNotPermitted handles a query whose domain is not allowlisted. For A/AAAA
// it first tries the IP allowlist (resolve and keep only allowlisted IPs); if
// that does not apply it sinkholes. Other query types get NXDOMAIN.
func (handler *dnsHandler) handleNotPermitted(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) {
	enforce := (qtype == dns.TypeA || qtype == dns.TypeAAAA)
	if !enforce {
		handler.handleBlockedNonEnforcedType(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)

		return
	}

	// Domain is not allowlisted, but it may resolve to an allowlisted IP; if so,
	// respond with only those IPs.
	if handler.resolveViaIPAllowlist(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID) {
		return
	}

	handler.handleBlockedEnforcedType(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)
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
		fields := handler.dnsLogFields("BLOCKED", qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "note", "sinkholed-not-allowlisted")
		lg.Warn("dns.blocked", fields...)
	}

	message := new(dns.Msg)
	message.SetReply(request)
	message.Answer = sinkholeAnswer(request.Question[0].Name, qtype)

	_ = writer.WriteMsg(message)
}

// sinkholeAnswer builds the zero-address record (0.0.0.0 / ::) used to sinkhole
// an A/AAAA query without leaking a real IP.
func sinkholeAnswer(name string, qtype uint16) []dns.RR {
	switch qtype {
	case dns.TypeA:
		return []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   net.IPv4(0, 0, 0, 0),
		}}
	case dns.TypeAAAA:
		return []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
			AAAA: net.IPv6zero,
		}}
	default:
		return nil
	}
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
		fields := handler.dnsLogFields("BLOCKED", qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "note", "nxdomain")
		lg.Warn("dns.blocked", fields...)
	}

	handler.respondWithError(writer, request, dns.RcodeNameError)
}

// handleAllowedRequest forwards allowed DNS queries to upstream servers and returns
// the response. fullyPermitted is false for audited (would-be-blocked) queries: those
// already logged their AUDIT verdict and must not enter the dns-strict resolved set.
func (handler *dnsHandler) handleAllowedRequest(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
	fullyPermitted bool,
) {
	resp, err := handler.forward(request)
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

	if handler.blockExfilResponse(lg, writer, request, resp, qname, qtype, remoteAddr, remotePort, flowID) {
		return
	}

	// dns-strict: push the resolved IPs into the kernel set BEFORE the client sees
	// the answer, so its immediate connect doesn't race the set update.
	if fullyPermitted {
		handler.reportResolvedIPs(lg, resp, qname)
	}

	if lg != nil && fullyPermitted {
		fields := handler.dnsLogFields("ALLOWED", qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "rcode", rcodeString(resp.Rcode))
		lg.Info("dns.allowed", fields...)
	}

	_ = writer.WriteMsg(resp)
}

// resolveViaIPAllowlist handles a non-allowlisted domain that may point at an
// allowlisted IP: it resolves upstream and, if any answer IP is in the IP
// allowlist, replies with only those records. Returns false to fall through to
// the normal sinkhole. It never widens the dns-strict resolved set: the static
// IP allowlist already permits these destinations at the packet level.
func (handler *dnsHandler) resolveViaIPAllowlist(
	lg *slog.Logger,
	writer dns.ResponseWriter,
	request *dns.Msg,
	qname string,
	qtype uint16,
	remoteAddr string,
	remotePort int,
	flowID string,
) bool {
	if handler.ipAllow == nil || handler.ipAllow.len() == 0 {
		return false
	}

	resp, err := handler.forward(request)
	if err != nil || resp == nil {
		return false
	}

	if handler.blockExfilResponse(lg, writer, request, resp, qname, qtype, remoteAddr, remotePort, flowID) {
		return true
	}

	kept := handler.filterToAllowlistedIPs(resp)
	if len(kept) == 0 {
		// No allowlisted IP for this record type. If the domain reaches an
		// allowlisted IP via the other address family (e.g. an AAAA probe for an
		// IPv4-only allowlisted host), the sinkhole here is expected: answer it
		// without raising a false BLOCKED alert.
		if handler.siblingResolvesToAllowlistedIP(qname, qtype) {
			handler.answerSinkholeSibling(lg, writer, request, qname, qtype, remoteAddr, remotePort, flowID)

			return true
		}

		return false
	}

	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.Answer = kept

	if lg != nil {
		fields := handler.dnsLogFields("ALLOWED", qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "note", "ip-allowlisted")
		lg.Info("dns.allowed", fields...)
	}

	_ = writer.WriteMsg(reply)

	return true
}

// siblingResolvesToAllowlistedIP reports whether qname resolves to an allowlisted
// IP in the other address family (A<->AAAA). A per-family sinkhole stays silent
// when the domain is still reachable, so a dual-stack client's unmatched query
// does not raise a false BLOCKED alert.
func (handler *dnsHandler) siblingResolvesToAllowlistedIP(qname string, qtype uint16) bool {
	sibling := siblingQtype(qtype)
	if sibling == 0 {
		return false
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), sibling)

	resp, err := handler.forward(req)
	if err != nil || resp == nil {
		return false
	}

	return len(handler.filterToAllowlistedIPs(resp)) > 0
}

func siblingQtype(qtype uint16) uint16 {
	switch qtype {
	case dns.TypeA:
		return dns.TypeAAAA
	case dns.TypeAAAA:
		return dns.TypeA
	default:
		return 0
	}
}

// answerSinkholeSibling replies to an A/AAAA query whose own family has no
// allowlisted IP but whose sibling family does. It returns the zero-address
// sinkhole (0.0.0.0 / ::) rather than an empty NODATA answer: a positive answer
// stops the stub resolver from walking its search list, which would otherwise
// emit spurious BLOCKED alerts for suffixed names. The host is reachable via the
// sibling family, so this logs ALLOWED without an alert.
func (handler *dnsHandler) answerSinkholeSibling(
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
		fields := handler.dnsLogFields("ALLOWED", qname, qtype, remoteAddr, remotePort, flowID)
		fields = append(fields, "note", "ip-allowlisted-other-family")
		lg.Info("dns.allowed", fields...)
	}

	message := new(dns.Msg)
	message.SetReply(request)
	message.Answer = sinkholeAnswer(request.Question[0].Name, qtype)

	_ = writer.WriteMsg(message)
}

// filterToAllowlistedIPs keeps only the A/AAAA answer records whose address is in
// the IP allowlist, so a filtered reply cannot leak non-allowlisted IPs. The CNAME
// chain is preserved alongside them, since resolvers may ignore terminal address
// records whose owner name is an unresolved alias. Returns nil when no address is
// allowlisted, so the caller falls through to the sinkhole.
func (handler *dnsHandler) filterToAllowlistedIPs(resp *dns.Msg) []dns.RR {
	var addrs, cnames []dns.RR

	for _, rr := range resp.Answer {
		switch rec := rr.(type) {
		case *dns.A:
			if handler.ipAllow.contains(rec.A) {
				addrs = append(addrs, rr)
			}
		case *dns.AAAA:
			if handler.ipAllow.contains(rec.AAAA) {
				addrs = append(addrs, rr)
			}
		case *dns.CNAME:
			cnames = append(cnames, rr)
		}
	}

	if len(addrs) == 0 {
		return nil
	}

	return append(cnames, addrs...)
}

// reportResolvedIPs hands the answer's A/AAAA addresses to the OnResolved hook.
func (handler *dnsHandler) reportResolvedIPs(lg *slog.Logger, resp *dns.Msg, qname string) {
	if handler.opts.OnResolved == nil || resp == nil {
		return
	}

	ips, ttl := extractAnswerIPs(resp)
	if len(ips) == 0 {
		return
	}

	if lg != nil {
		lg.Debug("dns.resolved_ips", "qname", qname, "ips", ips, "ttl", ttl)
	}

	handler.opts.OnResolved(ips, ttl, constraintsFor(qname, handler.opts.DomainRules))
}

// extractAnswerIPs collects the A/AAAA addresses in a DNS answer (CNAME-chased
// records included, since they appear in the same answer section) and the minimum
// TTL across them.
func extractAnswerIPs(resp *dns.Msg) ([]string, uint32) {
	var (
		ips     []string
		minTTL  uint32
		haveTTL bool
	)

	for _, rr := range resp.Answer {
		var ip net.IP

		switch record := rr.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			continue
		}

		if ip == nil {
			continue
		}

		ips = append(ips, ip.String())

		ttl := rr.Header().Ttl
		if !haveTTL || ttl < minTTL {
			minTTL = ttl
			haveTTL = true
		}
	}

	return ips, minTTL
}

// forward sends a DNS request to upstream servers, trying UDP first then TCP if truncated.
func (handler *dnsHandler) forward(request *dns.Msg) (*dns.Msg, error) {
	udpClient := &dns.Client{
		Net:     "udp",
		Timeout: handler.timeout,
		Dialer:  netutil.MarkedDNSDialer(handler.timeout), // SO_MARK bypasses nft REDIRECT
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
			// Retry once on a fresh source port: a concurrent forward may hold the rotated one.
			udpClient.Dialer = netutil.MarkedDNSDialer(handler.timeout)

			in, _, err = udpClient.ExchangeContext(ctx, request, up)
			if err != nil || in == nil {
				continue // try next upstream
			}
		}

		if !in.Truncated {
			return in, nil
		}

		// Response truncated, retry via TCP
		if handler.opts.Logger != nil {
			handler.opts.Logger.Debug("dns.upstream_truncated", "upstream", up, "retrying_tcp", true)
		}

		inTCP, _, err2 := tcpClient.ExchangeContext(ctx, request, up)
		if err2 == nil && inTCP != nil {
			return inTCP, nil
		}
		// try next upstream on TCP fail
	}

	return nil, os.ErrDeadlineExceeded
}

// markedDialer bypasses the local redirect rules for upstream DNS traffic.
func (handler *dnsHandler) markedDialer() *net.Dialer {
	return newMarkedDialer(handler.timeout)
}

// defaultUpstreamsFromEnv reads DNS_UPSTREAMS or returns Docker's resolver.
func defaultUpstreamsFromEnv() []string {
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
