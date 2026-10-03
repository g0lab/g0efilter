package nftables

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	nft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The generated ruleset text stays the single source of truth; this compiles the
// closed subset of nft syntax our templates emit into one atomic netlink batch.

var errRulesetSyntax = errors.New("unsupported nftables ruleset syntax")

const (
	protoICMP   = 1
	protoICMPv6 = 58

	kwTable   = "table"
	kwDaddr   = "daddr"
	familyIP  = "ip"
	familyIP6 = "ip6"

	// Concatenated set keys use the 32-bit registers that alias NFT_REG_1.
	reg32Concat = 8

	// About 100 bytes per element keeps a message's element list well under 64 KiB.
	elementsPerMessage = 256

	applyTimeout   = 10 * time.Second
	resolveTimeout = 3 * time.Second
)

//nolint:gochecknoglobals // read-only lookup tables for the compiler
var (
	familyByName = map[string]nft.TableFamily{familyIP: nft.TableFamilyIPv4, familyIP6: nft.TableFamilyIPv6}

	setTypes = map[string]nft.SetDatatype{
		"ipv4_addr":    nft.TypeIPAddr,
		"ipv6_addr":    nft.TypeIP6Addr,
		"inet_proto":   nft.TypeInetProto,
		"inet_service": nft.TypeInetService,
	}

	l4Protos = map[string]byte{"tcp": unix.IPPROTO_TCP, "udp": unix.IPPROTO_UDP}

	icmpTypes = map[string]byte{
		"echo-request":        8,
		"icmpv6:echo-request": 128,
		"nd-router-solicit":   133,
		"nd-router-advert":    134,
		"nd-neighbor-solicit": 135,
		"nd-neighbor-advert":  136,
	}

	icmpFamilies = map[string]struct {
		family  nft.TableFamily
		proto   byte
		keyType nft.SetDatatype
	}{
		"icmp":   {nft.TableFamilyIPv4, protoICMP, nft.TypeICMPType},
		"icmpv6": {nft.TableFamilyIPv6, protoICMPv6, nft.TypeICMP6Type},
	}

	chainTypes = map[string]nft.ChainType{"filter": nft.ChainTypeFilter, "nat": nft.ChainTypeNAT}

	chainHooks = map[string]*nft.ChainHook{
		"output":     nft.ChainHookOutput,
		"forward":    nft.ChainHookForward,
		"prerouting": nft.ChainHookPrerouting,
	}

	chainPolicies = map[string]nft.ChainPolicy{"policy accept": nft.ChainPolicyAccept, "policy drop": nft.ChainPolicyDrop}

	ctStates = map[string]uint32{
		"invalid":     expr.CtStateBitINVALID,
		"established": expr.CtStateBitESTABLISHED,
		"related":     expr.CtStateBitRELATED,
		"new":         expr.CtStateBitNEW,
	}
)

// CONCURRENCY: applies and dns-strict updates check their context under this lock,
// so an update from a retired service, whose context is canceled before the
// replacement is applied, can never land in the replacement's sets.
//
//nolint:gochecknoglobals // one lock for the process's single nftables state
var rulesetLock = make(chan struct{}, 1)

// applyRuleset replaces the managed tables in a single kernel transaction.
func applyRuleset(ctx context.Context, ruleset string) error {
	return withRuleset(ctx, applyTimeout, 16*len(ruleset), func(conn *nft.Conn) error {
		err := compileRuleset(conn, ruleset)
		if err != nil {
			return err
		}

		err = conn.Flush()
		if err != nil {
			return fmt.Errorf("apply nftables ruleset: %w", err)
		}

		return nil
	})
}

// withRuleset runs fn under the ruleset lock. timeout starts before the wait, so time
// queued behind another operation spends the same budget.
func withRuleset(ctx context.Context, timeout time.Duration, batchBytes int, fn func(*nft.Conn) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case rulesetLock <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("nftables: wait for ruleset lock: %w", ctx.Err())
	}

	defer func() { <-rulesetLock }()

	return withConn(ctx, timeout, batchBytes, fn)
}

// withConn bounds socket I/O by ctx and timeout. A batch goes out in one write with its
// acks queued behind it, so the buffers grow past the sysctl caps, as nft does.
func withConn(ctx context.Context, timeout time.Duration, batchBytes int, fn func(*nft.Conn) error) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	stop := func() bool { return true }

	conn, err := nft.New(nft.WithSockOptions(func(sock *netlink.Conn) error {
		setBuffers(sock, max(1<<20, batchBytes))

		watch, err := watchDeadline(ctx, sock, deadline)
		if err != nil {
			return err
		}

		stop = watch

		return nil
	}))
	if err != nil {
		return fmt.Errorf("open netlink: %w", err)
	}

	defer func() { stop() }()

	return fn(conn)
}

type deadliner interface {
	SetDeadline(t time.Time) error
}

// watchDeadline sets deadline before watching ctx, so a cancellation that lands
// during setup cannot be overwritten by it.
func watchDeadline(ctx context.Context, sock deadliner, deadline time.Time) (func() bool, error) {
	err := sock.SetDeadline(deadline)
	if err != nil {
		return nil, fmt.Errorf("set netlink deadline: %w", err)
	}

	return context.AfterFunc(ctx, func() { _ = sock.SetDeadline(time.Now()) }), nil
}

func setBuffers(sock *netlink.Conn, size int) {
	raw, err := sock.SyscallConn()
	if err != nil {
		return
	}

	_ = raw.Control(func(fd uintptr) {
		for _, opt := range [][2]int{
			{unix.SO_SNDBUFFORCE, unix.SO_SNDBUF},
			{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF},
		} {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt[0], size) != nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt[1], size)
			}
		}
	})
}

type tableDecl struct {
	table  *nft.Table
	sets   []setDecl
	chains []chainDecl
}

type setDecl struct {
	name     string
	types    []string
	interval bool
	timeout  bool
	elements []string
}

type chainDecl struct {
	name  string
	decl  []string
	rules [][]string
}

type parser struct {
	lines []string
	pos   int
}

// compileRuleset queues the ruleset on conn without sending it.
func compileRuleset(conn *nft.Conn, ruleset string) error {
	p := &parser{lines: rulesetLines(ruleset)}

	for ; p.pos < len(p.lines); p.pos++ {
		err := p.statement(conn)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *parser) statement(conn *nft.Conn) error {
	fields := strings.Fields(p.lines[p.pos])

	if args, ok := exactly(fields, kwTable, "$", "$"); ok {
		table, err := tableRef(args[0], args[1])
		if err == nil {
			conn.AddTable(table)
		}

		return err
	}

	if args, ok := exactly(fields, "delete", kwTable, "$", "$"); ok {
		table, err := tableRef(args[0], args[1])
		if err == nil {
			conn.DelTable(table)
		}

		return err
	}

	if args, ok := exactly(fields, kwTable, "$", "$", "{"); ok {
		block, err := p.table(args[0], args[1])
		if err != nil {
			return err
		}

		return block.emit(conn)
	}

	return fmt.Errorf("%w: %q", errRulesetSyntax, p.lines[p.pos])
}

// body calls fn for each line of the block opened on the current line.
func (p *parser) body(what string, fn func(line string) error) error {
	for p.pos++; p.pos < len(p.lines); p.pos++ {
		if p.lines[p.pos] == "}" {
			return nil
		}

		err := fn(p.lines[p.pos])
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("%w: %s is not closed", errRulesetSyntax, what)
}

func (p *parser) table(family, name string) (tableDecl, error) {
	table, err := tableRef(family, name)
	if err != nil {
		return tableDecl{}, err
	}

	block := tableDecl{table: table}

	err = p.body("table "+name, func(line string) error {
		fields := strings.Fields(line)

		if args, ok := exactly(fields, "set", "$", "{"); ok {
			set, err := p.set(args[0])
			block.sets = append(block.sets, set)

			return err
		}

		if args, ok := exactly(fields, "chain", "$", "{"); ok {
			chain, err := p.chain(args[0])
			block.chains = append(block.chains, chain)

			return err
		}

		return fmt.Errorf("%w: %q", errRulesetSyntax, line)
	})

	return block, err
}

func (p *parser) set(name string) (setDecl, error) {
	set := setDecl{name: name}

	err := p.body("set "+name, set.parse)
	if err == nil && len(set.types) == 0 {
		err = fmt.Errorf("%w: set %s has no type", errRulesetSyntax, name)
	}

	return set, err
}

func (s *setDecl) parse(line string) error {
	body, isElements := strings.CutPrefix(line, "elements = {")

	switch {
	case strings.HasPrefix(line, "type "):
		s.types = strings.Split(strings.TrimPrefix(line, "type "), " . ")
	case line == "flags interval":
		s.interval = true
	case line == "flags timeout":
		s.timeout = true
	case isElements && strings.HasSuffix(body, "}"):
		for element := range strings.SplitSeq(strings.TrimSuffix(body, "}"), ",") {
			if element = strings.TrimSpace(element); element != "" {
				s.elements = append(s.elements, element)
			}
		}
	default:
		return fmt.Errorf("%w: %q", errRulesetSyntax, line)
	}

	return nil
}

func (p *parser) chain(name string) (chainDecl, error) {
	chain := chainDecl{name: name}

	err := p.body("chain "+name, func(line string) error {
		if strings.HasPrefix(line, "type ") {
			chain.decl = strings.Fields(strings.ReplaceAll(line, ";", " "))

			return nil
		}

		tokens, err := tokenize(line)
		chain.rules = append(chain.rules, tokens)

		return err
	})

	return chain, err
}

// exactly matches fields against a pattern of literals and "$" captures.
func exactly(fields []string, pattern ...string) ([]string, bool) {
	if len(fields) != len(pattern) {
		return nil, false
	}

	return matchPattern(pattern, fields)
}

// rulesetLines drops comments and blank lines; our templates never quote a '#'.
func rulesetLines(ruleset string) []string {
	var lines []string

	for line := range strings.SplitSeq(ruleset, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}

	return lines
}

func tableRef(family, name string) (*nft.Table, error) {
	f, ok := familyByName[family]
	if !ok {
		return nil, fmt.Errorf("%w: table family %q", errRulesetSyntax, family)
	}

	return &nft.Table{Family: f, Name: name}, nil
}

// tokenize keeps quoted strings and {...} groups as single tokens.
func tokenize(line string) ([]string, error) {
	var tokens []string

	for rest := strings.TrimSpace(line); rest != ""; rest = strings.TrimLeft(rest, " \t") {
		length := tokenLen(rest)
		if length == 0 {
			return nil, fmt.Errorf("%w: unterminated token in %q", errRulesetSyntax, line)
		}

		tokens = append(tokens, rest[:length])
		rest = rest[length:]
	}

	return tokens, nil
}

// tokenLen returns 0 for an unterminated quote or group.
func tokenLen(s string) int {
	switch s[0] {
	case '"':
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return end + 2
		}

		return 0
	case '{':
		return strings.IndexByte(s, '}') + 1
	}

	if end := strings.IndexAny(s, " \t"); end >= 0 {
		return end
	}

	return len(s)
}

func (b tableDecl) emit(conn *nft.Conn) error {
	err := b.emitObjects(conn)
	if err != nil {
		return fmt.Errorf("table %s: %w", b.table.Name, err)
	}

	return nil
}

func (b tableDecl) emitObjects(conn *nft.Conn) error {
	conn.AddTable(b.table)

	sets := make(map[string]*nft.Set, len(b.sets))

	for _, block := range b.sets {
		set, elements, err := block.build(b.table)
		if err != nil {
			return err
		}

		err = addSet(conn, set, elements)
		if err != nil {
			return fmt.Errorf("set %s: %w", block.name, err)
		}

		sets[block.name] = set
	}

	// Chains first: a jump may target a chain declared later in the table.
	chains := make([]*nft.Chain, len(b.chains))

	for i, block := range b.chains {
		chain, err := block.build(b.table)
		if err != nil {
			return err
		}

		chains[i] = conn.AddChain(chain)
	}

	compiler := ruleCompiler{conn: conn, table: b.table, sets: sets}

	for i, block := range b.chains {
		for _, tokens := range block.rules {
			exprs, err := compiler.compile(tokens)
			if err != nil {
				return fmt.Errorf("chain %s: %w", block.name, err)
			}

			conn.AddRule(&nft.Rule{Table: b.table, Chain: chains[i], Exprs: exprs})
		}
	}

	return nil
}

func addSet(conn *nft.Conn, set *nft.Set, elements []nft.SetElement) error {
	err := conn.AddSet(set, nil)
	if err != nil {
		return fmt.Errorf("add set: %w", err)
	}

	return queueElements(conn.SetAddElements, set, elements)
}

// queueElements chunks elements: a message's element list is one netlink
// attribute, whose 16-bit length silently wraps past 64 KiB.
func queueElements(queue func(*nft.Set, []nft.SetElement) error, set *nft.Set, elements []nft.SetElement) error {
	for chunk := range slices.Chunk(elements, elementsPerMessage) {
		err := queue(set, chunk)
		if err != nil {
			return fmt.Errorf("queue set %s elements: %w", set.Name, err)
		}
	}

	return nil
}

func (c chainDecl) build(table *nft.Table) (*nft.Chain, error) {
	chain := &nft.Chain{Name: c.name, Table: table}
	if c.decl == nil {
		return chain, nil
	}

	args, ok := matchPattern([]string{"type", "$", "hook", "$", "priority", "$"}, c.decl)
	if !ok {
		return nil, fmt.Errorf("%w: chain %s declaration %v", errRulesetSyntax, c.name, c.decl)
	}

	chainType, okType := chainTypes[args[0]]
	hook, okHook := chainHooks[args[1]]
	priority, okPriority := chainPriority(args[2])
	policy, okPolicy := chainPolicy(c.decl[6:])

	if !okType || !okHook || !okPriority || !okPolicy {
		return nil, fmt.Errorf("%w: chain %s declaration %v", errRulesetSyntax, c.name, c.decl)
	}

	chain.Type, chain.Hooknum, chain.Priority, chain.Policy = chainType, hook, new(priority), policy

	return chain, nil
}

func chainPolicy(rest []string) (*nft.ChainPolicy, bool) {
	if len(rest) == 0 {
		return nil, true
	}

	policy, ok := chainPolicies[strings.Join(rest, " ")]

	return &policy, ok
}

func chainPriority(value string) (nft.ChainPriority, bool) {
	switch value {
	case "filter":
		return 0, true
	case "dstnat":
		return -100, true
	}

	priority, err := strconv.ParseInt(value, 10, 32)

	return nft.ChainPriority(priority), err == nil
}

func (s *setDecl) build(table *nft.Table) (*nft.Set, []nft.SetElement, error) {
	types := make([]nft.SetDatatype, len(s.types))

	for i, name := range s.types {
		datatype, ok := setTypes[name]
		if !ok {
			return nil, nil, fmt.Errorf("%w: set %s type %q", errRulesetSyntax, s.name, name)
		}

		types[i] = datatype
	}

	set := &nft.Set{
		Table:         table,
		Name:          s.name,
		KeyType:       types[0],
		Interval:      s.interval,
		HasTimeout:    s.timeout,
		Concatenation: len(types) > 1,
	}

	if set.Concatenation {
		set.KeyType = nft.MustConcatSetType(types...)
	}

	elements, err := encodeElements(s.elements, set.Concatenation)
	if err != nil {
		return nil, nil, fmt.Errorf("set %s: %w", s.name, err)
	}

	return set, elements, nil
}

// span is an inclusive address range; tail holds the encoded proto/port of a concat element.
type span struct {
	first, last netip.Addr
	tail        []byte
}

// encodeElements encodes interval elements. Overlapping entries are merged because the
// kernel rejects them, and the union admits exactly the same destinations.
func encodeElements(entries []string, concat bool) ([]nft.SetElement, error) {
	spans := make([]span, 0, len(entries))

	for _, entry := range entries {
		s, err := parseSpan(entry, concat)
		if err != nil {
			return nil, err
		}

		spans = append(spans, s)
	}

	var elements []nft.SetElement

	for _, s := range mergeSpans(spans) {
		if concat {
			elements = append(elements, nft.SetElement{
				Key:    append(s.first.AsSlice(), s.tail...),
				KeyEnd: append(s.last.AsSlice(), s.tail...),
			})

			continue
		}

		elements = append(elements, nft.SetElement{Key: s.first.AsSlice()})

		// The interval end is exclusive, so a range reaching the top address has none.
		if next := s.last.Next(); next.IsValid() && next.Is4() == s.last.Is4() {
			elements = append(elements, nft.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}

	return elements, nil
}

func parseSpan(entry string, concat bool) (span, error) {
	addr, tail := entry, []byte(nil)

	if concat {
		parts := strings.Split(entry, " . ")
		if len(parts) != 3 {
			return span{}, fmt.Errorf("%w: element %q", errRulesetSyntax, entry)
		}

		proto, okProto := l4Protos[parts[1]]
		port, err := strconv.ParseUint(parts[2], 10, 16)

		if !okProto || err != nil {
			return span{}, fmt.Errorf("%w: element %q", errRulesetSyntax, entry)
		}

		addr = parts[0]
		tail = concatTail(proto, uint16(port))
	}

	first, last, err := addrRange(addr)
	if err != nil {
		return span{}, fmt.Errorf("%w: element %q", errRulesetSyntax, entry)
	}

	return span{first: first, last: last, tail: tail}, nil
}

// concatTail encodes the proto and port fields, each padded to a 32-bit register.
func concatTail(proto byte, port uint16) []byte {
	return slices.Concat([]byte{proto, 0, 0, 0}, binaryutil.BigEndian.PutUint16(port), []byte{0, 0})
}

func addrRange(entry string) (netip.Addr, netip.Addr, error) {
	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("parse address: %w", err)
		}

		return addr, addr, nil
	}

	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("parse prefix: %w", err)
	}

	prefix = prefix.Masked()
	last := prefix.Addr().AsSlice()

	for bit := prefix.Bits(); bit < len(last)*8; bit++ {
		last[bit/8] |= 0x80 >> (bit % 8)
	}

	end, _ := netip.AddrFromSlice(last)

	return prefix.Addr(), end, nil
}

func mergeSpans(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int {
		return cmp.Or(slices.Compare(a.tail, b.tail), a.first.Compare(b.first))
	})

	var merged []span

	for _, s := range spans {
		if n := len(merged) - 1; n >= 0 && slices.Equal(merged[n].tail, s.tail) &&
			s.first.Compare(merged[n].last) <= 0 {
			if s.last.Compare(merged[n].last) > 0 {
				merged[n].last = s.last
			}

			continue
		}

		merged = append(merged, s)
	}

	return merged
}

type ruleCompiler struct {
	conn  *nft.Conn
	table *nft.Table
	sets  map[string]*nft.Set
}

// rulePattern matches literal tokens; "$" captures one token for build.
type rulePattern struct {
	tokens []string
	build  func(c ruleCompiler, args []string) ([]expr.Any, error)
}

//nolint:gochecknoglobals // read-only grammar; longer forms precede their prefixes
var rulePatterns = []rulePattern{
	{[]string{"$", kwDaddr, ".", "meta", "l4proto", ".", "th", "dport", "$"}, ruleCompiler.daddrProtoPortIn},
	{[]string{"fib", kwDaddr, ".", "iif", "oifname", "$"}, ruleCompiler.fibOifname},
	{[]string{"$", kwDaddr, "$"}, ruleCompiler.daddr},
	{[]string{"oifname", "$"}, ifnameMatch(expr.MetaKeyOIFNAME)},
	{[]string{"iifname", "$"}, ifnameMatch(expr.MetaKeyIIFNAME)},
	{[]string{"ct", "state", "$"}, ruleCompiler.ctState},
	{[]string{"meta", "mark", "$"}, ruleCompiler.metaMark},
	{[]string{"$", "dport", "$"}, ruleCompiler.dport},
	{[]string{"$", "type", "$"}, ruleCompiler.icmpType},
	{[]string{"log", "prefix", "$", "group", "$"}, ruleCompiler.log},
	{[]string{"redirect", "to", "$"}, ruleCompiler.redirect},
	{[]string{"jump", "$"}, ruleCompiler.jump},
	{[]string{"accept"}, verdict(expr.VerdictAccept)},
	{[]string{"drop"}, verdict(expr.VerdictDrop)},
	{[]string{"return"}, verdict(expr.VerdictReturn)},
}

func (c ruleCompiler) compile(tokens []string) ([]expr.Any, error) {
	var exprs []expr.Any

	for len(tokens) > 0 {
		matched := false

		for _, pattern := range rulePatterns {
			args, ok := matchPattern(pattern.tokens, tokens)
			if !ok {
				continue
			}

			built, err := pattern.build(c, args)
			if errors.Is(err, errNoMatch) {
				continue
			}

			if err != nil {
				return nil, err
			}

			exprs = append(exprs, built...)
			tokens = tokens[len(pattern.tokens):]
			matched = true

			break
		}

		if !matched {
			return nil, fmt.Errorf("%w: %q", errRulesetSyntax, strings.Join(tokens, " "))
		}
	}

	return exprs, nil
}

// errNoMatch lets a builder decline a pattern whose captured keyword it does not handle.
var errNoMatch = errors.New("no match")

func matchPattern(pattern, tokens []string) ([]string, bool) {
	if len(tokens) < len(pattern) {
		return nil, false
	}

	var args []string

	for i, want := range pattern {
		switch {
		case want == "$":
			args = append(args, tokens[i])
		case want != tokens[i]:
			return nil, false
		}
	}

	return args, true
}

func (c ruleCompiler) addrHeader(keyword string, register uint32) (*expr.Payload, int, error) {
	switch {
	case keyword == familyIP && c.table.Family == nft.TableFamilyIPv4:
		return &expr.Payload{DestRegister: register, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, 4, nil
	case keyword == familyIP6 && c.table.Family == nft.TableFamilyIPv6:
		return &expr.Payload{DestRegister: register, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, 16, nil
	case keyword == familyIP || keyword == familyIP6:
		return nil, 0, fmt.Errorf("%w: %s daddr in a %s table", errRulesetSyntax, keyword, c.table.Name)
	default:
		return nil, 0, errNoMatch
	}
}

func (c ruleCompiler) set(name string) (*nft.Set, error) {
	set, ok := c.sets[strings.TrimPrefix(name, "@")]
	if !strings.HasPrefix(name, "@") || !ok {
		return nil, fmt.Errorf("%w: unknown set %q", errRulesetSyntax, name)
	}

	return set, nil
}

func (c ruleCompiler) daddr(args []string) ([]expr.Any, error) {
	payload, size, err := c.addrHeader(args[0], 1)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(args[1], "@") {
		set, err := c.set(args[1])
		if err != nil {
			return nil, err
		}

		return []expr.Any{payload, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}, nil
	}

	addr, err := netip.ParseAddr(args[1])
	if err != nil || addr.BitLen()/8 != size {
		return nil, fmt.Errorf("%w: daddr %q", errRulesetSyntax, args[1])
	}

	return []expr.Any{payload, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()}}, nil
}

func (c ruleCompiler) daddrProtoPortIn(args []string) ([]expr.Any, error) {
	payload, _, err := c.addrHeader(args[0], reg32Concat)
	if err != nil {
		return nil, err
	}

	set, err := c.set(args[1])
	if err != nil {
		return nil, err
	}

	// Each concatenated field starts at a register boundary, so the address width sets the offsets.
	protoReg := reg32Concat + payload.Len/4

	return []expr.Any{
		payload,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: protoReg},
		transportPayload(protoReg+1, 2, 2),
		&expr.Lookup{SourceRegister: reg32Concat, SetName: set.Name, SetID: set.ID},
	}, nil
}

func (c ruleCompiler) dport(args []string) ([]expr.Any, error) {
	proto, ok := l4Protos[args[0]]
	if !ok {
		return nil, errNoMatch
	}

	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: dport %q", errRulesetSyntax, args[1])
	}

	return append(l4ProtoIs(proto),
		transportPayload(1, 2, 2),
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
	), nil
}

func (c ruleCompiler) icmpType(args []string) ([]expr.Any, error) {
	icmp, ok := icmpFamilies[args[0]]
	if !ok || icmp.family != c.table.Family {
		return nil, fmt.Errorf("%w: %s type in a %s table", errRulesetSyntax, args[0], c.table.Name)
	}

	types, err := icmpTypeValues(args[0], args[1])
	if err != nil {
		return nil, err
	}

	exprs := append(l4ProtoIs(icmp.proto), transportPayload(1, 0, 1))

	if !strings.HasPrefix(args[1], "{") {
		return append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{types[0]}}), nil
	}

	set := &nft.Set{Table: c.table, Anonymous: true, Constant: true, KeyType: icmp.keyType}

	elements := make([]nft.SetElement, len(types))
	for i, value := range types {
		elements[i] = nft.SetElement{Key: []byte{value}}
	}

	err = c.conn.AddSet(set, elements)
	if err != nil {
		return nil, fmt.Errorf("icmp type set: %w", err)
	}

	return append(exprs, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}), nil
}

func icmpTypeValues(keyword, value string) ([]byte, error) {
	names := []string{value}
	if strings.HasPrefix(value, "{") {
		names = strings.Split(strings.Trim(value, "{} "), ",")
	}

	values := make([]byte, 0, len(names))

	for _, name := range names {
		name = strings.TrimSpace(name)

		code, ok := icmpTypes[keyword+":"+name]
		if !ok {
			code, ok = icmpTypes[name]
		}

		if !ok {
			return nil, fmt.Errorf("%w: %s type %q", errRulesetSyntax, keyword, name)
		}

		values = append(values, code)
	}

	return values, nil
}

func (c ruleCompiler) fibOifname(args []string) ([]expr.Any, error) {
	name, err := ifnameBytes(args[0])
	if err != nil {
		return nil, err
	}

	return []expr.Any{
		&expr.Fib{Register: 1, FlagDADDR: true, FlagIIF: true, ResultOIFNAME: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
	}, nil
}

func ifnameMatch(key expr.MetaKey) func(ruleCompiler, []string) ([]expr.Any, error) {
	return func(_ ruleCompiler, args []string) ([]expr.Any, error) {
		name, err := ifnameBytes(args[0])
		if err != nil {
			return nil, err
		}

		return []expr.Any{
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
		}, nil
	}
}

// ifnameBytes pads an exact name to IFNAMSIZ; a trailing '*' compares only the prefix.
func ifnameBytes(quoted string) ([]byte, error) {
	name, err := strconv.Unquote(quoted)
	if err != nil || name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("%w: interface %s", errRulesetSyntax, quoted)
	}

	if prefix, ok := strings.CutSuffix(name, "*"); ok {
		return []byte(prefix), nil
	}

	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)

	return padded, nil
}

func (ruleCompiler) ctState(args []string) ([]expr.Any, error) {
	var bits uint32

	for state := range strings.SplitSeq(args[0], ",") {
		bit, ok := ctStates[state]
		if !ok {
			return nil, fmt.Errorf("%w: ct state %q", errRulesetSyntax, state)
		}

		bits |= bit
	}

	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}, nil
}

func (ruleCompiler) metaMark(args []string) ([]expr.Any, error) {
	mark, err := strconv.ParseUint(args[0], 0, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: mark %q", errRulesetSyntax, args[0])
	}

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark))},
	}, nil
}

func (ruleCompiler) log(args []string) ([]expr.Any, error) {
	prefix, err := strconv.Unquote(args[0])
	if err != nil || args[1] != "0" {
		return nil, fmt.Errorf("%w: log prefix %s group %s", errRulesetSyntax, args[0], args[1])
	}

	return []expr.Any{&expr.Log{Key: 1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_GROUP, Data: []byte(prefix)}}, nil
}

func (ruleCompiler) redirect(args []string) ([]expr.Any, error) {
	port, err := strconv.ParseUint(strings.TrimPrefix(args[0], ":"), 10, 16)
	if err != nil || !strings.HasPrefix(args[0], ":") {
		return nil, fmt.Errorf("%w: redirect to %q", errRulesetSyntax, args[0])
	}

	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		&expr.Redir{RegisterProtoMin: 1},
	}, nil
}

func (ruleCompiler) jump(args []string) ([]expr.Any, error) {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: args[0]}}, nil
}

func verdict(kind expr.VerdictKind) func(ruleCompiler, []string) ([]expr.Any, error) {
	return func(ruleCompiler, []string) ([]expr.Any, error) {
		return []expr.Any{&expr.Verdict{Kind: kind}}, nil
	}
}

func l4ProtoIs(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func transportPayload(register, offset, length uint32) *expr.Payload {
	return &expr.Payload{DestRegister: register, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length}
}

// Probe confirms this process can reach nftables over netlink, which needs CAP_NET_ADMIN.
func Probe(ctx context.Context) error {
	return withConn(ctx, applyTimeout, 0, func(conn *nft.Conn) error {
		_, err := conn.ListTables()
		if err != nil {
			return fmt.Errorf("list nftables tables: %w", err)
		}

		return nil
	})
}
