package filter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/safeio"
)

var errFailedCapture = errors.New("failed to capture client hello")

// Serve443 starts the TLS SNI filter.
func Serve443(ctx context.Context, allowlist []string, opts Options) error {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":8443"
	}

	return serveTCP(ctx, opts.ListenAddr, opts.Logger, handle, allowlist, opts)
}

func handle(conn net.Conn, allowlist []string, opts Options) error {
	defer safeio.CloseWithErr(nil, conn)

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	// 1) Extract SNI from ClientHello
	sni, cr, err := extractSNIFromConnection(conn, opts)
	if err != nil {
		return err
	}

	// 2) Check if SNI is blocked
	if sni == "" || !allowedHost(sni, allowlist) {
		handleBlockedSNI(conn, tc, sni, opts)

		return nil
	}

	// 3) Handle allowed SNI connection
	return handleAllowedSNI(conn, tc, cr, sni, opts)
}

// extractSNIFromConnection extracts SNI from TLS ClientHello.
func extractSNIFromConnection(conn net.Conn, opts Options) (string, io.Reader, error) {
	_ = conn.SetReadDeadline(time.Now().Add(connectionReadTimeout))

	ch, cr, err := peekClientHello(conn)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Info("sni.blocked",
				"component", "sni",
				"action", "BLOCKED",
				"reason", "peek-failed",
				"err", err.Error(),
				"src", conn.RemoteAddr().String(),
			)
		}

		return "", nil, err
	}

	_ = conn.SetReadDeadline(time.Time{})

	sni := strings.TrimSuffix(strings.ToLower(ch.ServerName), ".")

	return sni, cr, nil
}

// handleBlockedSNI handles blocked SNI connections.
func handleBlockedSNI(conn net.Conn, tc *net.TCPConn, sni string, opts Options) {
	if opts.Logger != nil {
		logBlockedSNI(conn, tc, sni, opts)
	}

	if opts.DropWithRST {
		_ = tc.SetLinger(0)
	}
}

// logBlockedSNI logs blocked SNI attempts.
func logBlockedSNI(conn net.Conn, tc *net.TCPConn, sni string, opts Options) {
	reason := "not-allowlisted"
	if sni == "" {
		reason = "no-sni"
	}

	sourceIP, sourcePort := sourceAddr(conn)

	var destIP string

	var destPort int

	tgt, derr := originalDstTCP(tc)
	if derr == nil {
		_ = EmitSynthetic(opts.Logger, "sni", conn, tc, tgt)
		destIP, destPort = parseHostPort(tgt)
	} else {
		opts.Logger.Debug("sni.orig_dst_unavailable_for_blocked",
			"err", derr.Error(),
			"source_ip", sourceIP,
			"source_port", sourcePort,
		)
	}

	logBlockedConnection(opts, componentSNI, reason, sni, conn, destIP, destPort)
}

// handleAllowedSNI handles allowed SNI connections.
func handleAllowedSNI(conn net.Conn, tc *net.TCPConn, cr io.Reader, sni string, opts Options) error {
	// Recover original destination
	target, err := originalDstTCP(tc)
	if err != nil {
		if opts.Logger != nil {
			opts.Logger.Warn("sni.orig_dst_error", "err", err.Error())
		}

		return err
	}

	// Emit synthetic event and log
	if opts.Logger != nil {
		_ = EmitSynthetic(opts.Logger, "sni", conn, tc, target)
		logAllowedSNI(conn, target, sni, opts)
	}

	// Connect and splice
	return connectAndSpliceSNI(conn, cr, target, opts)
}

// logAllowedSNI logs allowed SNI connections.
func logAllowedSNI(conn net.Conn, target, sni string, opts Options) {
	logAllowedConnection(opts, componentSNI, target, sni, conn)
}

// connectAndSpliceSNI connects to backend and splices data.
func connectAndSpliceSNI(conn net.Conn, cr io.Reader, target string, opts Options) error {
	backend, err := createMarkedDialer(opts).Dial("tcp", target)
	if err != nil {
		logBackendDialError(opts, componentSNI, conn, target, err)

		return fmt.Errorf("dial backend %s: %w", target, err)
	}

	defer func() { _ = backend.Close() }()

	setConnTimeouts(conn, backend, opts)
	bidirectionalCopy(conn, backend, cr)

	return nil
}

// createMarkedDialer creates a dialer with SO_MARK set.
func createMarkedDialer(opts Options) *net.Dialer {
	return newDialerFromOptions(opts)
}

// logBackendDialError logs backend connection errors.
// removed: use common.logBackendDialError

// TLS ClientHello peek helpers

type roConn struct{ r io.Reader }

func (c roConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil {
		return n, fmt.Errorf("read error: %w", err)
	}

	return n, nil
}

func (c roConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c roConn) Close() error                     { return nil }
func (c roConn) LocalAddr() net.Addr              { return nil }
func (c roConn) RemoteAddr() net.Addr             { return nil }
func (c roConn) SetDeadline(time.Time) error      { return nil }
func (c roConn) SetReadDeadline(time.Time) error  { return nil }
func (c roConn) SetWriteDeadline(time.Time) error { return nil }

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	buf := new(bytes.Buffer)

	hello, err := readClientHello(io.TeeReader(reader, buf))
	if err != nil {
		return nil, nil, err
	}

	return hello, io.MultiReader(buf, reader), nil
}

func readClientHello(r io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	//nolint:gosec // TLS MinVersion intentionally low to capture ClientHello from older clients
	err := tls.Server(roConn{r}, &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *ch
			hello = &cp
			// Return a config that enforces TLS1.2 minimum for the actual handshake.
			// We capture the ClientHello above and then abort the handshake by
			// returning a config; older clients will fail the handshake which is
			// acceptable since we only need the ClientHello for SNI.
			return &tls.Config{MinVersion: tls.VersionTLS12}, nil
		},
	}).Handshake() //nolint:noctx
	if hello == nil {
		if err == nil {
			err = errFailedCapture
		}

		return nil, err
	}

	return hello, nil
}
