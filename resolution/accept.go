package resolution

import (
	"fmt"
	"strings"
)

// MediaRange is one element of an Accept value (RFC 9110 §12.5.1).
type MediaRange struct {
	// Type and Subtype are lowercase; either may be "*".
	Type, Subtype string
	// Params are the media type parameters other than q.
	Params []Param
	// Weight is the q value in thousandths (0 to 1000); 1000 when absent.
	Weight int
}

// Param is a media type parameter.
type Param struct {
	Name, Value string
}

// Matches reports whether the media range covers mediaType ("type/subtype",
// parameters ignored).
func (r MediaRange) Matches(mediaType string) bool {
	full, _, _ := strings.Cut(mediaType, ";")
	t, s, ok := strings.Cut(strings.ToLower(strings.TrimSpace(full)), "/")
	if !ok {
		return false
	}
	return (r.Type == "*" || r.Type == t) && (r.Subtype == "*" || r.Subtype == s)
}

// specificity orders matching media ranges (RFC 9110 §12.5.1: "Media
// ranges can be overridden by more specific media ranges or specific media
// types"): type/subtype over type/* over */*, then more parameters.
func (r MediaRange) specificity() int {
	s := len(r.Params)
	if r.Type != "*" {
		s += 1000
	}
	if r.Subtype != "*" {
		s += 1000
	}
	return s
}

// weight returns the weight ranges give mediaType: that of the most specific
// matching range, or -1 when no range matches.
func weight(ranges []MediaRange, mediaType string) int {
	best, w := -1, -1
	for _, r := range ranges {
		if r.Matches(mediaType) && r.specificity() > best {
			best, w = r.specificity(), r.Weight
		}
	}
	return w
}

// Negotiate returns the offer that accept prefers, following the content
// negotiation rules of RFC 9110 §12.5.1: an offer gets the weight of the most
// specific media range that matches it (parameters are not compared), an
// offer whose weight is 0 or that no range matches is not acceptable, and the
// acceptable offer with the highest weight wins, ties going to the earlier
// offer. An accept value without any element accepts every offer, so
// offers[0] is returned. A malformed accept value accepts nothing.
func Negotiate(accept string, offers []string) (string, bool) {
	ranges, err := ParseAccept(accept)
	if err != nil || len(offers) == 0 {
		return "", false
	}
	if len(ranges) == 0 {
		return offers[0], true
	}
	pick, best := "", 0
	for _, o := range offers {
		if w := weight(ranges, o); w > best {
			pick, best = o, w
		}
	}
	return pick, best > 0
}

// Acceptable reports whether accept accepts mediaType (Negotiate with the
// single offer mediaType).
func Acceptable(accept, mediaType string) bool {
	_, ok := Negotiate(accept, []string{mediaType})
	return ok
}

// ParseAccept parses an Accept value as defined in RFC 9110 §12.5.1:
// #( media-range [ weight ] ), where a media range is "*/*", type "/*" or
// type "/" subtype followed by parameters, and the weight is ";q=" qvalue.
// An empty value is a valid empty list.
func ParseAccept(s string) ([]MediaRange, error) {
	var out []MediaRange
	elements, err := splitOutsideQuotes(s, ',')
	if err != nil {
		return nil, err
	}
	for _, el := range elements {
		el = strings.Trim(el, " \t")
		if el == "" {
			continue
		}
		r, err := parseRange(el)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func parseRange(el string) (MediaRange, error) {
	parts, err := splitOutsideQuotes(el, ';')
	if err != nil {
		return MediaRange{}, err
	}
	typ, sub, ok := strings.Cut(strings.Trim(parts[0], " \t"), "/")
	if !ok || !isToken(typ) || !isToken(sub) || (typ == "*" && sub != "*") {
		return MediaRange{}, fmt.Errorf("resolution: %q is not a media range", parts[0])
	}
	r := MediaRange{Type: strings.ToLower(typ), Subtype: strings.ToLower(sub), Weight: 1000}
	for i, p := range parts[1:] {
		p = strings.Trim(p, " \t")
		if p == "" {
			continue
		}
		name, value, ok := strings.Cut(p, "=")
		if !ok || !isToken(name) || !isParamValue(value) {
			return MediaRange{}, fmt.Errorf("resolution: %q is not a media type parameter", p)
		}
		if strings.EqualFold(name, "q") {
			if r.Weight, err = parseQ(value); err != nil {
				return MediaRange{}, err
			}
			if i != len(parts)-2 {
				return MediaRange{}, fmt.Errorf("resolution: the weight must be the last parameter")
			}
			continue
		}
		r.Params = append(r.Params, Param{Name: strings.ToLower(name), Value: value})
	}
	return r, nil
}

// parseQ parses qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ).
func parseQ(v string) (int, error) {
	bad := fmt.Errorf("resolution: %q is not a qvalue", v)
	if v == "" || len(v) > 5 || (v[0] != '0' && v[0] != '1') {
		return 0, bad
	}
	if len(v) > 1 && v[1] != '.' {
		return 0, bad
	}
	w, scale := 0, 100
	for i := 2; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, bad
		}
		w += int(v[i]-'0') * scale
		scale /= 10
	}
	if v[0] == '1' {
		if w != 0 {
			return 0, bad
		}
		return 1000, nil
	}
	return w, nil
}

func isTchar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTchar(s[i]) {
			return false
		}
	}
	return true
}

// isParamValue reports token / quoted-string.
func isParamValue(s string) bool {
	if isToken(s) {
		return true
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++
			if i >= len(s)-1 {
				return false
			}
		case c == '"', c < 0x20 && c != '\t', c == 0x7f, c >= 0x80:
			return false
		}
	}
	return true
}

// splitOutsideQuotes splits s at sep outside quoted strings. Non-ASCII
// bytes and an unterminated quote are errors.
func splitOutsideQuotes(s string, sep byte) ([]string, error) {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80:
			return nil, fmt.Errorf("resolution: an Accept value is ASCII")
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if quoted {
		return nil, fmt.Errorf("resolution: unterminated quoted string")
	}
	return append(out, s[start:]), nil
}
