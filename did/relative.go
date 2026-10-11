package did

import (
	"fmt"
	"strings"
)

// Resolve resolves the reference u against an absolute base DID URL with
// the algorithm of RFC 3986 §5.2 (DID Core 1.0 §3.2.2, DID 1.1 §3.2.1).
// As DID Core 1.0 §3.2.2 states, the scheme is "did", the authority is
// method-name ":" method-specific-id, and path, query and fragment are those
// of the DID URL. A reference can therefore change the path, query and
// fragment but never the DID, unless it is an absolute DID URL.
//
// The zero DIDURL is the empty reference "". RFC 3986 §5.2.2 gives it the
// path and query of the base and its own, undefined, fragment, so it
// resolves to the base without its fragment (RFC 3986 §5.4.1 "" = base).
func (u DIDURL) Resolve(base DIDURL) (DIDURL, error) {
	if base.IsRelative() || base.IsZero() {
		return DIDURL{}, fmt.Errorf("did: the base of a reference must be an absolute DID URL")
	}
	t := DIDURL{did: base.did, query: u.query, hasQuery: u.hasQuery, fragment: u.fragment, hasFragment: u.hasFragment}
	switch {
	case !u.did.IsZero():
		t.did = u.did
		t.path = removeDotSegments(u.path)
	case u.path == "":
		t.path = base.path
		if !u.hasQuery {
			t.query, t.hasQuery = base.query, base.hasQuery
		}
	case strings.HasPrefix(u.path, "/"):
		t.path = removeDotSegments(u.path)
	default:
		t.path = removeDotSegments(merge(base.path, u.path))
	}
	out, err := ParseURL(t.String())
	if err != nil {
		return DIDURL{}, fmt.Errorf("%w: %w", errNotDIDURL, err)
	}
	return out, nil
}

// ParseRef parses a relative or absolute DID URL reference and resolves it
// against base, for example "#key-1" against did:example:123 gives
// did:example:123#key-1, and the empty reference "" gives did:example:123.
func ParseRef(ref string, base DID) (DIDURL, error) {
	u, err := ParseReference(ref)
	if err != nil {
		return DIDURL{}, err
	}
	return u.Resolve(base.URL())
}

// merge implements RFC 3986 §5.2.3 for a base with an authority.
func merge(basePath, ref string) string {
	i := strings.LastIndexByte(basePath, '/')
	if i < 0 {
		return "/" + ref
	}
	return basePath[:i+1] + ref
}

// removeDotSegments implements RFC 3986 §5.2.4.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			out = dropLast(out)
		case in == "/..":
			in = "/"
			out = dropLast(out)
		case in == "." || in == "..":
			in = ""
		default:
			j := strings.IndexByte(in[1:], '/')
			if j < 0 {
				out = append(out, in)
				in = ""
			} else {
				out = append(out, in[:j+1])
				in = in[j+1:]
			}
		}
	}
	return strings.Join(out, "")
}

func dropLast(s []string) []string {
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}
