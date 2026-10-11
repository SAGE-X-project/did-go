package did

import "strings"

// DIDURL is a DID URL, did-url = did path-abempty [ "?" query ] [ "#"
// fragment ], or a relative DID URL reference (DID Core 1.0 §3.2.2), which
// has no DID. Path, query and fragment are kept as written, without
// percent-decoding. The zero value is the empty reference "" (RFC 3986
// §4.2 relative-ref with an empty path); IsZero reports it.
type DIDURL struct {
	did         DID
	path        string
	query       string
	fragment    string
	hasQuery    bool
	hasFragment bool
}

// DID returns the DID of an absolute DID URL, or the zero DID for a relative
// reference.
func (u DIDURL) DID() DID { return u.did }

// Path returns the path: path-abempty for an absolute DID URL, the relative
// path for a relative reference.
func (u DIDURL) Path() string { return u.path }

// Query returns the query without "?".
func (u DIDURL) Query() string { return u.query }

// HasQuery reports whether a "?" is present, even with an empty query.
func (u DIDURL) HasQuery() bool { return u.hasQuery }

// Fragment returns the fragment without "#".
func (u DIDURL) Fragment() string { return u.fragment }

// HasFragment reports whether a "#" is present, even with an empty fragment.
func (u DIDURL) HasFragment() bool { return u.hasFragment }

// IsRelative reports whether u is a relative reference (it has no DID). The
// zero value is also the empty reference "" but reports false, so that an
// absent DID URL is never taken for a reference to resolve; a caller that
// accepts the empty reference checks IsZero.
func (u DIDURL) IsRelative() bool { return u.did.IsZero() && !u.IsZero() }

// IsZero reports whether u is the zero value.
func (u DIDURL) IsZero() bool { return u == DIDURL{} }

// IsDID reports whether u is an absolute DID URL without path, query or
// fragment.
func (u DIDURL) IsDID() bool {
	return !u.did.IsZero() && u.path == "" && !u.hasQuery && !u.hasFragment
}

// WithoutFragment returns u without its fragment.
func (u DIDURL) WithoutFragment() DIDURL {
	u.fragment, u.hasFragment = "", false
	return u
}

// String returns the DID URL as written.
func (u DIDURL) String() string {
	var sb strings.Builder
	sb.WriteString(u.did.String())
	sb.WriteString(u.path)
	if u.hasQuery {
		sb.WriteByte('?')
		sb.WriteString(u.query)
	}
	if u.hasFragment {
		sb.WriteByte('#')
		sb.WriteString(u.fragment)
	}
	return sb.String()
}

// ParseURL parses an absolute DID URL.
func ParseURL(s string) (DIDURL, error) {
	if len(s) > MaxLength {
		return DIDURL{}, syntaxErr("", MaxLength, "input longer than MaxLength")
	}
	d, i, err := parseDID(s)
	if err != nil {
		return DIDURL{}, err
	}
	u := DIDURL{did: d}
	if err := parseTail(s, i, &u); err != nil {
		return DIDURL{}, err
	}
	return u, nil
}

// ParseReference parses an absolute DID URL or a relative DID URL
// reference. A relative reference follows RFC 3986 relative-ref with a
// path-absolute, path-noscheme or empty path; a network-path reference
// ("//...") would replace the DID and is not supported. The empty reference
// "" is a relative-ref of RFC 3986 §4.2 and parses to the zero DIDURL, which
// Resolve turns into the base without its fragment (RFC 3986 §5.4.1).
func ParseReference(s string) (DIDURL, error) {
	if hasScheme(s) {
		return ParseURL(s)
	}
	if len(s) > MaxLength {
		return DIDURL{}, syntaxErr("", MaxLength, "input longer than MaxLength")
	}
	if s == "" {
		return DIDURL{}, nil
	}
	if strings.HasPrefix(s, "//") {
		return DIDURL{}, syntaxErr(s, 0, "a network-path reference cannot form a DID URL")
	}
	var u DIDURL
	end := strings.IndexAny(s, "?#")
	if end < 0 {
		end = len(s)
	}
	if err := checkRelativePath(s, end); err != nil {
		return DIDURL{}, err
	}
	u.path = s[:end]
	if err := parseQueryFragment(s, end, &u); err != nil {
		return DIDURL{}, err
	}
	return u, nil
}

// checkRelativePath checks s[:end] as path-absolute, path-noscheme or
// path-empty of RFC 3986 §4.2.
func checkRelativePath(s string, end int) error {
	firstSegment := true
	for i := 0; i < end; i++ {
		c := s[i]
		switch {
		case c == '/':
			firstSegment = false
		case c == ':' && firstSegment:
			return syntaxErr(s, i, `the first segment of a relative path must not contain ":"`)
		case c == '%':
			if err := checkPct(s, i); err != nil {
				return err
			}
			i += 2
		case !isPchar(c):
			return syntaxErr(s, i, "character not allowed in a path")
		}
	}
	return nil
}

// parseTail parses path-abempty [ "?" query ] [ "#" fragment ] from s[i:].
func parseTail(s string, i int, u *DIDURL) error {
	start := i
	for i < len(s) && s[i] != '?' && s[i] != '#' {
		c := s[i]
		switch {
		case c == '/':
		case c == '%':
			if err := checkPct(s, i); err != nil {
				return err
			}
			i += 2
		case !isPchar(c):
			return syntaxErr(s, i, "character not allowed in a path")
		}
		i++
	}
	if i > start && s[start] != '/' {
		return syntaxErr(s, start, `a path must start with "/"`)
	}
	u.path = s[start:i]
	return parseQueryFragment(s, i, u)
}

// parseQueryFragment parses [ "?" query ] [ "#" fragment ] from s[i:].
func parseQueryFragment(s string, i int, u *DIDURL) error {
	if i < len(s) && s[i] == '?' {
		end, err := scanQueryChars(s, i+1, true)
		if err != nil {
			return err
		}
		u.query, u.hasQuery = s[i+1:end], true
		i = end
	}
	if i < len(s) && s[i] == '#' {
		end, err := scanQueryChars(s, i+1, false)
		if err != nil {
			return err
		}
		u.fragment, u.hasFragment = s[i+1:end], true
		i = end
	}
	if i != len(s) {
		return syntaxErr(s, i, "unexpected character")
	}
	return nil
}

// scanQueryChars scans *( pchar / "/" / "?" ) from s[i:]. In a query it
// stops at "#"; in a fragment "#" is an error.
func scanQueryChars(s string, i int, query bool) (int, error) {
	for i < len(s) {
		c := s[i]
		switch {
		case c == '#' && query:
			return i, nil
		case c == '/' || c == '?' || isPchar(c):
		case c == '%':
			if err := checkPct(s, i); err != nil {
				return 0, err
			}
			i += 2
		default:
			return 0, syntaxErr(s, i, "character not allowed in a query or fragment")
		}
		i++
	}
	return i, nil
}
