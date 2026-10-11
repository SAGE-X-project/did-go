package vm

import (
	"bytes"

	"github.com/sage-x-project/did-go/internal/multiformats"
)

// MultikeyCodec is one row of the Multikey key tables of CID 1.0 §2.2.2: the
// two-byte multicodec prefix, the length of the key data that follows and
// the statements that define the row.
type MultikeyCodec struct {
	// Name is the key type, for example "Ed25519".
	Name string
	// Prefix is the two-byte varint multicodec prefix.
	Prefix [2]byte
	// KeyLength is the number of key bytes after the prefix.
	KeyLength int
	// Secret is true for a secret key row.
	Secret bool
	// PrefixStatement is the requirement id of the prefix and length rule.
	PrefixStatement string
	// EncodingStatement is the requirement id of the base-58-btc encoding
	// rule, or "" where the specification states it without MUST.
	EncodingStatement string
}

// MultikeyCodecs returns the public and secret key rows of CID 1.0 §2.2.2,
// in a fresh slice.
//
// The BLS12-381 G2 secret key row states the prefix 0x8030 and calls it the
// varint expression of 0x130a, whose varint is 0x8a26. Both prefixes are
// listed so that either reading is accepted.
func MultikeyCodecs() []MultikeyCodec {
	return []MultikeyCodec{
		{"P-256", [2]byte{0x80, 0x24}, 33, false, "cid10#Multikey.6", "cid10#Multikey.7"},
		{"P-384", [2]byte{0x81, 0x24}, 49, false, "cid10#Multikey.8", ""},
		{"Ed25519", [2]byte{0xed, 0x01}, 32, false, "cid10#Multikey.9", "cid10#Multikey.10"},
		{"BLS12-381-G2", [2]byte{0xeb, 0x01}, 96, false, "cid10#Multikey.11", "cid10#Multikey.12"},
		{"SM2", [2]byte{0x86, 0x24}, 33, false, "cid10#Multikey.13", "cid10#Multikey.14"},
		{"P-256", [2]byte{0x86, 0x26}, 32, true, "cid10#Multikey.15", "cid10#Multikey.16"},
		{"P-384", [2]byte{0x87, 0x26}, 48, true, "cid10#Multikey.17", ""},
		{"Ed25519", [2]byte{0x80, 0x26}, 32, true, "cid10#Multikey.18", "cid10#Multikey.19"},
		{"BLS12-381-G2", [2]byte{0x80, 0x30}, 96, true, "cid10#Multikey.20", "cid10#Multikey.21"},
		{"BLS12-381-G2", [2]byte{0x8a, 0x26}, 96, true, "cid10#Multikey.20", "cid10#Multikey.21"},
		{"SM2", [2]byte{0x90, 0x26}, 32, true, "cid10#Multikey.22", "cid10#Multikey.23"},
	}
}

// LookupMultikey returns the row whose prefix starts data.
func LookupMultikey(data []byte) (MultikeyCodec, bool) {
	for _, c := range MultikeyCodecs() {
		if bytes.HasPrefix(data, c.Prefix[:]) {
			return c, true
		}
	}
	return MultikeyCodec{}, false
}

// DecodeMultikey decodes a Multikey value (publicKeyMultibase or
// secretKeyMultibase of a Multikey method): the base-58-btc header z, a known
// prefix of the expected kind (public or secret) and the key length of that
// row. It returns the row and the key bytes without the prefix.
func DecodeMultikey(value string, secret bool) (MultikeyCodec, []byte, error) {
	property := "publicKeyMultibase"
	statement := "cid10#Multikey.3"
	if secret {
		property, statement = "secretKeyMultibase", "cid10#Multikey.5"
	}
	if value == "" || value[0] != multiformats.HeaderBase58BTC {
		return MultikeyCodec{}, nil, errorf(property, "cid10#Multikey.10", "a Multikey value uses the base-58-btc header z")
	}
	_, data, err := multiformats.DecodeMultibase(value)
	if err != nil {
		return MultikeyCodec{}, nil, errorf(property, statement, "not a Multibase value: %v", err)
	}
	codec, ok := LookupMultikey(data)
	if !ok || codec.Secret != secret {
		kind := "public"
		if secret {
			kind = "secret"
		}
		return MultikeyCodec{}, nil, errorf(property, statement, "the value does not start with a known %s key header", kind)
	}
	if len(data) != len(codec.Prefix)+codec.KeyLength {
		return MultikeyCodec{}, nil, errorf(property, codec.PrefixStatement,
			"%s key data is %d bytes, want %d", codec.Name, len(data)-len(codec.Prefix), codec.KeyLength)
	}
	return codec, data[len(codec.Prefix):], nil
}

// EncodeMultikey prefixes key with the codec prefix and encodes the result
// with the base-58-btc header z.
func EncodeMultikey(codec MultikeyCodec, key []byte) (string, error) {
	if len(key) != codec.KeyLength {
		return "", errorf("key", codec.PrefixStatement, "%s key data is %d bytes, want %d", codec.Name, len(key), codec.KeyLength)
	}
	data := append(append([]byte(nil), codec.Prefix[:]...), key...)
	return multiformats.EncodeMultibase(multiformats.HeaderBase58BTC, data)
}

// checkMultibase applies the form check of DID Core 1.0 §5.2.1 and CID 1.0
// §2.4 to a publicKeyMultibase or secretKeyMultibase value of any method
// type: a Multibase header followed by at least one character, and, for the
// headers z and u that CID defines, characters of that alphabet.
func checkMultibase(property, statement, value string) error {
	if len(value) < 2 || !multiformats.IsHeader(value[0]) {
		return errorf(property, statement, "not a Multibase value")
	}
	if value[0] == multiformats.HeaderBase58BTC || value[0] == multiformats.HeaderBase64URL {
		if _, _, err := multiformats.DecodeMultibase(value); err != nil {
			return errorf(property, statement, "not a Multibase value: %v", err)
		}
	}
	return nil
}
