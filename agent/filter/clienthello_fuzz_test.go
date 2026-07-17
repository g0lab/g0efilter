//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// Differential fuzz against the previous crypto/tls extraction path.

type oracleConn struct{ r io.Reader }

func (c oracleConn) Read(p []byte) (int, error)       { return c.r.Read(p) } //nolint:wrapcheck // oracle shim
func (c oracleConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c oracleConn) Close() error                     { return nil }
func (c oracleConn) LocalAddr() net.Addr              { return nil }
func (c oracleConn) RemoteAddr() net.Addr             { return nil }
func (c oracleConn) SetDeadline(time.Time) error      { return nil }
func (c oracleConn) SetReadDeadline(time.Time) error  { return nil }
func (c oracleConn) SetWriteDeadline(time.Time) error { return nil }

// oracleSNI runs the pre-rewrite extraction path.
func oracleSNI(data []byte) (string, bool) {
	var hello *tls.ClientHelloInfo

	_ = tls.Server(oracleConn{r: bytes.NewReader(data)}, &tls.Config{ //nolint:exhaustruct // parse-only oracle
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *ch
			hello = &cp

			return nil, nil //nolint:nilnil // capture only
		},
	}).Handshake() //nolint:noctx // reader-backed, cannot block

	if hello == nil {
		return "", false
	}

	return hello.ServerName, true
}

func FuzzReadClientHelloSNI(f *testing.F) {
	f.Add(clientHelloBytes(f, "api.example.com"))
	f.Add(clientHelloBytes(f, ""))
	f.Add(clientHelloBytes(f, "xn--nxasmq6b.example"))
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		sni, err := readClientHelloSNI(bytes.NewReader(data)) // must never panic or hang

		want, ok := oracleSNI(data)
		if !ok {
			return // oracle could not parse: no agreement required
		}

		if err != nil {
			t.Fatalf("oracle extracted %q but parser errored: %v", want, err)
		}

		if sni != want {
			t.Fatalf("parser = %q, oracle = %q", sni, want)
		}
	})
}
