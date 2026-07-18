package filter

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// Small TLS ClientHello parser for SNI extraction without handshake overhead.

const (
	recordHeaderLen          = 5
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1
	handshakeHeaderLen       = 4
	extTypeServerName        = 0
	nameTypeHostName         = 0

	maxRecordSize      = 16384 + 2048
	maxClientHelloSize = 65536
)

var (
	errNotHandshake       = errors.New("not a TLS handshake record")
	errNotClientHello     = errors.New("not a ClientHello")
	errRecordLength       = errors.New("invalid TLS record length")
	errClientHelloTooBig  = errors.New("ClientHello exceeds size cap")
	errMalformedHello     = errors.New("malformed ClientHello")
	errMalformedExtension = errors.New("malformed ClientHello extension")
)

// readRecord reads one TLS record and returns its payload after checking it is
// a plausible handshake record.
func readRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, recordHeaderLen)

	_, err := io.ReadFull(r, hdr)
	if err != nil {
		return nil, fmt.Errorf("read record header: %w", err)
	}

	if hdr[0] != recordTypeHandshake {
		return nil, errNotHandshake
	}

	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen == 0 || recLen > maxRecordSize {
		return nil, errRecordLength
	}

	payload := make([]byte, recLen)

	_, err = io.ReadFull(r, payload)
	if err != nil {
		return nil, fmt.Errorf("read record payload: %w", err)
	}

	return payload, nil
}

// readClientHelloSNI reassembles the ClientHello handshake message from one or
// more TLS records and returns its SNI ("" when the extension is absent).
func readClientHelloSNI(r io.Reader) (string, error) {
	var (
		handshake []byte
		need      = -1 // total handshake bytes required; unknown until the header is read
	)

	for need < 0 || len(handshake) < need {
		payload, err := readRecord(r)
		if err != nil {
			return "", err
		}

		handshake = append(handshake, payload...)

		if need < 0 && len(handshake) >= handshakeHeaderLen {
			if handshake[0] != handshakeTypeClientHello {
				return "", errNotClientHello
			}

			bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if bodyLen > maxClientHelloSize {
				return "", errClientHelloTooBig
			}

			need = handshakeHeaderLen + bodyLen
		}
	}

	return parseClientHelloSNI(handshake[handshakeHeaderLen:need])
}

// parseClientHelloSNI extracts the server_name extension from a ClientHello body.
func parseClientHelloSNI(body []byte) (string, error) {
	s := cryptobyte.String(body)

	var sessionID, ciphers, compression cryptobyte.String
	if !s.Skip(2+32) || // legacy_version + random
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&ciphers) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return "", errMalformedHello
	}

	if s.Empty() {
		return "", nil // no extensions block, so no SNI
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return "", errMalformedHello
	}

	return sniFromExtensions(extensions)
}

// sniFromExtensions scans the extensions block for server_name (type 0).
func sniFromExtensions(extensions cryptobyte.String) (string, error) {
	for !extensions.Empty() {
		var (
			extType uint16
			extData cryptobyte.String
		)

		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return "", errMalformedExtension
		}

		if extType == extTypeServerName {
			return sniFromServerNameExt(extData)
		}
	}

	return "", nil
}

// sniFromServerNameExt returns the first host_name entry in a server_name extension.
func sniFromServerNameExt(extData cryptobyte.String) (string, error) {
	var names cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&names) {
		return "", errMalformedExtension
	}

	for !names.Empty() {
		var (
			nameType uint8
			name     cryptobyte.String
		)

		if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
			return "", errMalformedExtension
		}

		if nameType == nameTypeHostName {
			return string(name), nil
		}
	}

	return "", nil
}
