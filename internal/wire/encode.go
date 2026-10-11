package wire

import (
	"strconv"
	"unicode/utf8"
)

// Encode writes n as compact JSON. Members are written in the order of
// n.Members and strings are escaped by one fixed rule, so equal nodes give
// equal bytes (docs/00 NFR-1). Number text is written as it is; nodes built
// by this package always hold valid number text.
func Encode(n Node) []byte {
	return appendNode(nil, n)
}

func appendNode(dst []byte, n Node) []byte {
	switch n.Kind {
	case Bool:
		return strconv.AppendBool(dst, n.Bool)
	case Number:
		return append(dst, n.Text...)
	case String:
		return AppendString(dst, n.Text)
	case Array:
		dst = append(dst, '[')
		for i, item := range n.Items {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendNode(dst, item)
		}
		return append(dst, ']')
	case Object:
		dst = append(dst, '{')
		for i, m := range n.Members {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = AppendString(dst, m.Name)
			dst = append(dst, ':')
			dst = appendNode(dst, m.Value)
		}
		return append(dst, '}')
	}
	return append(dst, "null"...)
}

const hexDigits = "0123456789abcdef"

// AppendString appends s as a JSON string. It escapes '"', '\\' and the
// control characters below U+0020 (with the short forms \b \f \n \r \t where
// they exist) and writes every other character as UTF-8. s must be valid
// UTF-8; callers check values before encoding.
func AppendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			_, size := utf8.DecodeRuneInString(s[i:])
			dst = append(dst, s[i:i+size]...)
			i += size
			continue
		}
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			} else {
				dst = append(dst, c)
			}
		}
		i++
	}
	return append(dst, '"')
}
