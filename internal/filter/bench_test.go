//nolint:testpackage // Benchmarks exercise unexported hot-path functions.
package filter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func makeAllowlist(n int) []string {
	patterns := make([]string, 0, n+2)
	patterns = append(patterns, "*.cdn.example.com", `/^cache-[0-9]+\.example\.net$/`)

	for i := range n {
		patterns = append(patterns, fmt.Sprintf("host-%04d.example.com", i))
	}

	return NormalizePatterns(patterns)
}

func BenchmarkAllowedHost(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		matcher := newMatcher(makeAllowlist(size))
		hit := fmt.Sprintf("host-%04d.example.com", size-1)
		miss := "definitely-not-allowlisted.example.org"

		b.Run(fmt.Sprintf("size=%d/hit", size), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				if !matcher.allows(hit) {
					b.Fatal("expected hit")
				}
			}
		})

		b.Run(fmt.Sprintf("size=%d/miss", size), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				if matcher.allows(miss) {
					b.Fatal("expected miss")
				}
			}
		})
	}
}

func BenchmarkMatchPattern(b *testing.B) {
	const host = "api.example.com"

	cases := map[string]string{
		"exact":    "api.example.com",
		"wildcard": "*.example.com",
		"regex":    `/^api\.example\.com$/`,
	}

	for name, pattern := range cases {
		if !matchPattern(host, pattern) { // warm the cache
			b.Fatalf("pattern %q should match %q", pattern, host)
		}

		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = matchPattern(host, pattern)
			}
		})
	}
}

// helloCaptureConn stops the handshake after capturing the ClientHello.
type helloCaptureConn struct{ buf *bytes.Buffer }

func (c *helloCaptureConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *helloCaptureConn) Write(p []byte) (int, error) {
	n, err := c.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("capture write: %w", err)
	}

	return n, nil
}

func (c *helloCaptureConn) Close() error                     { return nil }
func (c *helloCaptureConn) LocalAddr() net.Addr              { return nil }
func (c *helloCaptureConn) RemoteAddr() net.Addr             { return nil }
func (c *helloCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *helloCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *helloCaptureConn) SetWriteDeadline(time.Time) error { return nil }

func clientHelloBytes(tb testing.TB, serverName string) []byte {
	tb.Helper()

	buf := &bytes.Buffer{}

	//nolint:gosec // capturing a ClientHello only, no real connection
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	_ = tls.Client(&helloCaptureConn{buf: buf}, cfg).HandshakeContext(context.Background())

	if buf.Len() == 0 {
		tb.Fatal("failed to capture ClientHello bytes")
	}

	return buf.Bytes()
}

func BenchmarkPeekClientHello(b *testing.B) {
	hello := clientHelloBytes(b, "api.example.com")

	sni, _, err := peekClientHello(bytes.NewReader(hello))
	if err != nil || sni != "api.example.com" {
		b.Fatalf("peekClientHello sanity check failed: sni=%q err=%v", sni, err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(hello)))

	for range b.N {
		_, _, loopErr := peekClientHello(bytes.NewReader(hello))
		if loopErr != nil {
			b.Fatal(loopErr)
		}
	}
}

func BenchmarkReadHeadWithTextproto(b *testing.B) {
	const req = "GET /path/to/resource HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"User-Agent: bench/1.0\r\n" +
		"Accept: */*\r\n" +
		"Accept-Encoding: gzip, deflate\r\n\r\n"

	b.ReportAllocs()
	b.SetBytes(int64(len(req)))

	for range b.N {
		br := bufio.NewReader(strings.NewReader(req))

		_, _, err := readHeadWithTextproto(br)
		if err != nil {
			b.Fatal(err)
		}
	}
}
