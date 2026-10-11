// Package multiformats implements the Multibase, Multihash and varint
// encodings that Controlled Identifiers v1.0 §2.4, §2.5, §3.1 and §3.2
// require. It is pure: no I/O and no global mutable state.
package multiformats

import (
	"errors"
	"fmt"
	"strings"
)

// Alphabets of CID 1.0 §2.4.
const (
	// AlphabetBase58BTC is the base-58-btc alphabet (Multibase header z).
	AlphabetBase58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// AlphabetBase64URL is the base-64-url-no-pad alphabet (Multibase header u).
	AlphabetBase64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// errEmptyAlphabet reports an alphabet that cannot encode anything.
var errEmptyAlphabet = errors.New("multiformats: alphabet must have at least two characters")

// expansion returns the size bound of CID §3.1 and §3.2 using integer
// arithmetic: ceil(n * log(from) / log(to)) + 1. log(from)/log(to) is bounded
// from above by bits(from)/floor-bits(to), which keeps the arithmetic integral.
func expansion(n, from, to int) int {
	return n*ceilLog2(from)/floorLog2(to) + 1
}

func ceilLog2(n int) int {
	b := 0
	for v := 1; v < n; v <<= 1 {
		b++
	}
	return b
}

func floorLog2(n int) int {
	b := 0
	for v := n; v > 1; v >>= 1 {
		b++
	}
	return b
}

// BaseEncode applies CID 1.0 §3.1 Base Encode to bytes with the given
// alphabet; the target base is the length of the alphabet. Every leading zero
// byte becomes one leading first-alphabet character.
func BaseEncode(data []byte, alphabet string) (string, error) {
	base := len(alphabet)
	if base < 2 {
		return "", errEmptyAlphabet
	}
	zeroes := 0
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	size := expansion(len(data)-zeroes, 256, base)
	digits := make([]int, size)
	length := 0
	for _, b := range data[zeroes:] {
		carry := int(b)
		i := 0
		for pos := size - 1; (carry != 0 || i < length) && pos >= 0; pos-- {
			carry += 256 * digits[pos]
			digits[pos] = carry % base
			carry /= base
			i++
		}
		length = i
	}
	pos := size - length
	for pos < size && digits[pos] == 0 {
		pos++
	}
	var sb strings.Builder
	sb.Grow(zeroes + size - pos)
	sb.WriteString(strings.Repeat(alphabet[:1], zeroes))
	for ; pos < size; pos++ {
		sb.WriteByte(alphabet[digits[pos]])
	}
	return sb.String(), nil
}

// BaseDecode applies CID 1.0 §3.2 Base Decode to an encoded string with the
// given alphabet. A character outside the alphabet is an error.
func BaseDecode(encoded, alphabet string) ([]byte, error) {
	base := len(alphabet)
	if base < 2 {
		return nil, errEmptyAlphabet
	}
	var values [256]int
	for i := range values {
		values[i] = -1
	}
	for i := 0; i < base; i++ {
		values[alphabet[i]] = i
	}
	zeroes := 0
	for zeroes < len(encoded) && encoded[zeroes] == alphabet[0] {
		zeroes++
	}
	size := expansion(len(encoded)-zeroes, base, 256)
	decoded := make([]int, size)
	length := 0
	for idx := zeroes; idx < len(encoded); idx++ {
		carry := values[encoded[idx]]
		if carry < 0 {
			return nil, fmt.Errorf("multiformats: character %q at position %d is not in the alphabet", encoded[idx], idx)
		}
		i := 0
		for pos := size - 1; (carry != 0 || i < length) && pos >= 0; pos-- {
			carry += base * decoded[pos]
			decoded[pos] = carry % 256
			carry /= 256
			i++
		}
		length = i
	}
	pos := size - length
	for pos < size && decoded[pos] == 0 {
		pos++
	}
	out := make([]byte, zeroes, zeroes+size-pos)
	for ; pos < size; pos++ {
		out = append(out, byte(decoded[pos]))
	}
	return out, nil
}
