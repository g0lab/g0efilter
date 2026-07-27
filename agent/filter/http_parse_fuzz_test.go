//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bufio"
	"bytes"
	"testing"
)

// The raw HTTP path exists so a transparent proxy forwards exactly what the
// client sent. Everything it writes to the backend must therefore be a verbatim
// prefix of what it read: no invented bytes, no reordering, no re-serialisation.

func httpParseSeeds(f *testing.F) {
	f.Helper()

	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 4\r\n\r\nbody"))
	f.Add([]byte("POST /x HTTP/1.1\r\nHost: a.example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"4;ext=v\r\ndata\r\n0\r\nX-Trailer: kept\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("not HTTP"))
	f.Add([]byte{})
}

func FuzzReadRawHTTPHeadBytes(f *testing.F) {
	httpParseSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		head, err := readRawHTTPHeadBytes(bufio.NewReader(bytes.NewReader(data))) // must never panic

		if len(head) > maxHTTPHeadBytes {
			t.Fatalf("head is %d bytes, cap is %d", len(head), maxHTTPHeadBytes)
		}

		if !bytes.HasPrefix(data, head) {
			t.Fatalf("head is not a prefix of the input: %q", head)
		}

		// A head read without error is terminated by a blank line.
		if err == nil && !bytes.HasSuffix(head, []byte("\n")) {
			t.Fatalf("head returned without error but is unterminated: %q", head)
		}
	})
}

// FuzzForwardRawRequest pins the verbatim-forwarding invariant across the head
// and every body framing: fixed length, chunked, and chunked with trailers.
func FuzzForwardRawRequest(f *testing.F) {
	httpParseSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		src := bufio.NewReader(bytes.NewReader(data))

		req, head, err := readRawHTTPRequestHead(src)
		if err != nil {
			return // unparseable heads are dropped, not forwarded
		}

		var forwarded bytes.Buffer

		forwarded.Write(head)

		// Errors are expected on malformed bodies; the invariant still has to hold
		// for whatever was written before the failure.
		_ = copyRawHTTPRequestBody(&forwarded, src, req)

		if !bytes.HasPrefix(data, forwarded.Bytes()) {
			t.Fatalf("forwarded bytes are not a verbatim prefix of the input\n got: %q\nfrom: %q",
				forwarded.Bytes(), data)
		}
	})
}
