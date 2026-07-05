//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

type headCase struct {
	name     string
	request  string
	wantHost string
	wantErr  bool
}

func readHeadCases() []headCase {
	return []headCase{
		{
			"missing host header",
			"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
			"",
			false,
		},
		{
			"port stripped from host",
			"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
			"example.com",
			false,
		},
		{
			"host lowercased and trailing dot trimmed",
			"GET / HTTP/1.1\r\nHost: EXAMPLE.Com.\r\n\r\n",
			"example.com",
			false,
		},
		{
			"multiple host headers uses first",
			"GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n",
			"first.com",
			false,
		},
		{
			"truncated request line",
			"GET / HT",
			"",
			true,
		},
		{
			"headers never terminated",
			"GET / HTTP/1.1\r\nHost: example.com\r\n",
			"",
			true,
		},
		{
			"empty input",
			"",
			"",
			true,
		},
		{
			"garbage bytes",
			"\x16\x03\x01\x02\x00\x01",
			"",
			true,
		},
	}
}

func TestReadHeadWithTextprotoEdgeCases(t *testing.T) {
	t.Parallel()

	for _, tt := range readHeadCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			br := bufio.NewReader(strings.NewReader(tt.request))

			host, head, err := readHeadWithTextproto(br)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}

			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}

			// Consumed bytes must be preserved even on error so permissive modes can forward
			if len(tt.request) > 0 && err != nil && len(head) == 0 {
				t.Error("consumed bytes must be returned on parse error")
			}
		})
	}
}

func TestPeekClientHelloNonTLS(t *testing.T) {
	t.Parallel()

	// Plain HTTP bytes are not a ClientHello: error, but consumed bytes preserved
	input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

	sni, buf, err := peekClientHello(strings.NewReader(input))
	if err == nil || sni != "" {
		t.Fatal("non-TLS data must not produce an SNI")
	}

	if buf == nil || buf.Len() == 0 {
		t.Error("consumed bytes must be preserved on error")
	}
}

func TestPeekClientHelloTruncated(t *testing.T) {
	t.Parallel()

	// A real ClientHello prefix, cut off mid-record
	full := clientHelloBytes(t, "example.com")

	sni, buf, err := peekClientHello(bytes.NewReader(full[:20]))
	if err == nil || sni != "" {
		t.Fatal("truncated ClientHello must error")
	}

	if buf == nil {
		t.Error("buffer must be returned on error")
	}
}

func TestPeekClientHelloWithSNI(t *testing.T) {
	t.Parallel()

	raw := clientHelloBytes(t, "sni.example.com")

	sni, buf, err := peekClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}

	if sni != "sni.example.com" {
		t.Errorf("sni = %q, want sni.example.com", sni)
	}

	if !bytes.Equal(buf.Bytes(), raw) {
		t.Error("peeked bytes must be preserved verbatim for splicing")
	}
}

func TestPeekClientHelloWithoutSNI(t *testing.T) {
	t.Parallel()

	raw := clientHelloBytes(t, "")

	sni, _, err := peekClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}

	if sni != "" {
		t.Errorf("sni = %q, want empty for SNI-less hello", sni)
	}
}
