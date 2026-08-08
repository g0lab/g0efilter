//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bytes"
	"testing"
)

// Splitting the ClientHello across TLS records is the standard way to hide the SNI
// from a filter that inspects only the first record. Extraction has to survive it,
// down to one byte per record.
func TestReadClientHelloSNIAcrossFragmentedRecords(t *testing.T) {
	t.Parallel()

	const host = "api.example.com"

	hello := clientHelloBytes(t, host)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "single record", data: hello},
		{name: "split after one byte", data: fragmentRecord(t, hello, 1)},
		{name: "split in the middle", data: fragmentRecord(t, hello, (len(hello)-5)/2)},
		{name: "split before the last byte", data: fragmentRecord(t, hello, len(hello)-6)},
		{name: "one byte per record", data: shredRecord(t, hello)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sni, err := readClientHelloSNI(bytes.NewReader(tc.data))
			if err != nil {
				t.Fatalf("extract: %v", err)
			}

			if sni != host {
				t.Errorf("sni = %q, want %q", sni, host)
			}
		})
	}
}

// shredRecord re-frames a handshake record as one record per byte.
func shredRecord(tb testing.TB, record []byte) []byte {
	tb.Helper()

	const headerLen = 5

	body := record[headerLen:]
	out := make([]byte, 0, len(body)*(headerLen+1))

	for _, b := range body {
		out = append(out, recordHeader(record[:headerLen], 1)...)
		out = append(out, b)
	}

	return out
}
