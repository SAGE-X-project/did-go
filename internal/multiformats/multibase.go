package multiformats

import (
	"encoding/base64"
	"fmt"
)

// Multibase headers of CID 1.0 §2.4.
const (
	HeaderBase58BTC byte = 'z'
	HeaderBase64URL byte = 'u'
)

// knownHeaders are the single-character headers of the Multibase registry.
// CID 1.0 §2.4 defines z and u normatively and allows others ("Other
// Multibase encoding values MAY be used").
const knownHeaders = "0179fFvVtTbBcChkKZzmMuUp"

// IsHeader reports whether c is a Multibase header character.
func IsHeader(c byte) bool {
	for i := 0; i < len(knownHeaders); i++ {
		if knownHeaders[i] == c {
			return true
		}
	}
	return false
}

// alphabetFor returns the CID 1.0 alphabet of a header, or "" when CID does
// not define one.
func alphabetFor(header byte) string {
	switch header {
	case HeaderBase58BTC:
		return AlphabetBase58BTC
	case HeaderBase64URL:
		return AlphabetBase64URL
	}
	return ""
}

// EncodeMultibase encodes data with the alphabet of header (z or u) using CID
// 1.0 §3.1 and prepends the header (CID 1.0 §2.4).
func EncodeMultibase(header byte, data []byte) (string, error) {
	alphabet := alphabetFor(header)
	if alphabet == "" {
		return "", fmt.Errorf("multiformats: header %q is not defined by CID 1.0", header)
	}
	s, err := BaseEncode(data, alphabet)
	if err != nil {
		return "", err
	}
	return string(header) + s, nil
}

// DecodeMultibase decodes a Multibase string whose header is z or u: the
// characters after the header are decoded with CID 1.0 §3.2 and that header's
// alphabet (CID 1.0 §2.4). It returns the header with the bytes.
func DecodeMultibase(s string) (byte, []byte, error) {
	if s == "" {
		return 0, nil, fmt.Errorf("multiformats: empty Multibase value")
	}
	header := s[0]
	alphabet := alphabetFor(header)
	if alphabet == "" {
		return header, nil, fmt.Errorf("multiformats: header %q is not defined by CID 1.0", header)
	}
	data, err := BaseDecode(s[1:], alphabet)
	if err != nil {
		return header, nil, err
	}
	return header, data, nil
}

// EncodeBase64URL encodes data as base64url without padding (RFC 4648 §5),
// the encoding JOSE uses (RFC 7515 §2). It is not the Multibase u encoding,
// which follows CID 1.0 §3.1.
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes base64url without padding (RFC 4648 §5).
func DecodeBase64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("multiformats: invalid base64url: %w", err)
	}
	return b, nil
}
