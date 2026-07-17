//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bytes"
	"errors"
	"testing"
)

// splitIntoRecords re-frames a single-record handshake as n TLS records, to
// exercise ClientHello reassembly across record boundaries.
func splitIntoRecords(t *testing.T, hello []byte, n int) []byte {
	t.Helper()

	if len(hello) < 6 || hello[0] != recordTypeHandshake {
		t.Fatal("input is not a single TLS handshake record")
	}

	payload := hello[5:]
	chunk := (len(payload) + n - 1) / n

	var out bytes.Buffer

	for off := 0; off < len(payload); off += chunk {
		end := min(off+chunk, len(payload))
		part := payload[off:end]

		//nolint:gosec // record chunks are far below the uint16 max
		out.Write([]byte{hello[0], hello[1], hello[2], byte(len(part) >> 8), byte(len(part))})
		out.Write(part)
	}

	return out.Bytes()
}

type sniCase struct {
	name    string
	data    []byte
	want    string
	wantErr error
}

func sniCases(t *testing.T) []sniCase {
	t.Helper()

	realHello := clientHelloBytes(t, "api.example.com")
	noSNIHello := clientHelloBytes(t, "")

	return []sniCase{
		{
			name: "real ClientHello with SNI",
			data: realHello,
			want: "api.example.com",
		},
		{
			name: "real ClientHello without SNI",
			data: noSNIHello,
			want: "",
		},
		{
			name: "ClientHello fragmented across records",
			data: splitIntoRecords(t, realHello, 3),
			want: "api.example.com",
		},
		{
			name:    "empty input",
			data:    []byte{},
			wantErr: errAny,
		},
		{
			name:    "non-handshake record type",
			data:    []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
			wantErr: errNotHandshake,
		},
		{
			name:    "handshake record but not a ClientHello",
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
			wantErr: errNotClientHello,
		},
		{
			name:    "zero-length record",
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0x00},
			wantErr: errRecordLength,
		},
		{
			name: "claimed handshake size over cap",
			// ClientHello header claiming a 16MB-1 body
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff},
			wantErr: errClientHelloTooBig,
		},
		{
			name:    "truncated mid-record",
			data:    realHello[:20],
			wantErr: errAny,
		},
		{
			name: "garbage ClientHello body",
			// Valid framing, body too short for version+random
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 1, 2, 3, 4},
			wantErr: errMalformedHello,
		},
	}
}

func TestReadClientHelloSNI(t *testing.T) {
	t.Parallel()

	for _, tt := range sniCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := readClientHelloSNI(bytes.NewReader(tt.data))

			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("readClientHelloSNI() unexpected error: %v", err)
				}

				if got != tt.want {
					t.Errorf("readClientHelloSNI() = %q, want %q", got, tt.want)
				}
			case errors.Is(tt.wantErr, errAny):
				if err == nil {
					t.Fatal("readClientHelloSNI() expected an error")
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("readClientHelloSNI() error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

// errAny marks table entries that only assert that some error occurred.
var errAny = errors.New("any error")

func TestPeekClientHelloPreservesBytesOnError(t *testing.T) {
	t.Parallel()

	// Under default-allow, consumed bytes must be replayable even when parsing
	// fails, so a non-TLS connection can still be spliced.
	garbage := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	_, buf, err := peekClientHello(bytes.NewReader(garbage))
	if err == nil {
		t.Fatal("expected parse error for garbage input")
	}

	if buf.Len() == 0 {
		t.Fatal("consumed bytes were not preserved in the buffer")
	}

	if !bytes.Equal(buf.Bytes(), garbage[:buf.Len()]) {
		t.Error("preserved bytes do not match what was consumed")
	}
}

func TestPeekClientHelloMatchesTLSClient(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"example.com", "sub.domain.example.org", "xn--nxasmq6b.example"} {
		hello := clientHelloBytes(t, host)

		sni, buf, err := peekClientHello(bytes.NewReader(hello))
		if err != nil {
			t.Fatalf("peekClientHello(%q hello): %v", host, err)
		}

		if sni != host {
			t.Errorf("sni = %q, want %q", sni, host)
		}

		if !bytes.Equal(buf.Bytes(), hello) {
			t.Errorf("buffer should hold the full consumed hello (%d of %d bytes)", buf.Len(), len(hello))
		}
	}
}
