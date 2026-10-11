package vm

import (
	"net/url"
	"strings"
)

// defaultPort returns the default port of a URL Standard special scheme
// that requires a host (file is special but may have an empty host).
func defaultPort(scheme string) (string, bool) {
	switch scheme {
	case "http", "ws":
		return "80", true
	case "https", "wss":
		return "443", true
	case "ftp":
		return "21", true
	}
	return "", false
}

// IsURL reports whether s is a valid URL string in the sense of the URL
// Standard, as CID 1.0 and DID 1.1 require for service ids and endpoint
// strings. Relative URL strings are valid URL strings. The check rejects
// characters the URL Standard does not allow (spaces, controls, "\", "<",
// ">", '"', "`", "{", "}", "|", "^"), malformed percent-encodings, a malformed
// scheme, and a special scheme (http, https, ws, wss, ftp) without a host.
func IsURL(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f || strings.IndexByte(`\<>"`+"`{}|^", c) >= 0 {
			return false
		}
		if c == '%' && !pctAt(s, i) {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme == "" {
		return true
	}
	if !validScheme(u.Scheme) {
		return false
	}
	if _, special := defaultPort(strings.ToLower(u.Scheme)); special && u.Host == "" {
		return false
	}
	return true
}

// IsURI reports whether s is a URI conforming to RFC 3986 §3: an absolute
// URI with a scheme, made only of unreserved, reserved and percent-encoded
// characters, with "[" and "]" only around an IP literal host.
func IsURI(s string) bool {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || !validScheme(scheme) {
		return false
	}
	if strings.Count(rest, "#") > 1 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == '%':
			if !pctAt(rest, i) {
				return false
			}
		case c == '[' || c == ']':
			if !inIPLiteral(rest, i) {
				return false
			}
		case !isURIChar(c):
			return false
		}
	}
	_, err := url.Parse(s)
	return err == nil
}

// IsNormalizedURI reports whether s is an RFC 3986 URI already in the normal
// form of RFC 3986 §6.2.2 and §6.2.3: lowercase scheme and host, uppercase
// percent-encoding hex digits, no percent-encoded unreserved characters, no
// dot segments, no empty or default port, and "/" as the path of an http(s)
// URI with an authority and an empty path.
func IsNormalizedURI(s string) bool {
	if !IsURI(s) {
		return false
	}
	scheme, rest, _ := strings.Cut(s, ":")
	if scheme != strings.ToLower(scheme) || !normalizedPct(rest) {
		return false
	}
	hier, _, _ := strings.Cut(rest, "#")
	hier, _, _ = strings.Cut(hier, "?")
	path := hier
	if strings.HasPrefix(hier, "//") {
		authority := hier[2:]
		if i := strings.IndexByte(authority, '/'); i >= 0 {
			authority, path = authority[:i], authority[i:]
		} else {
			path = ""
		}
		if !normalizedAuthority(scheme, authority) {
			return false
		}
		if path == "" && (scheme == "http" || scheme == "https") {
			return false
		}
	}
	return removeDotSegments(path) == path
}

func normalizedAuthority(scheme, authority string) bool {
	hostport := authority
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		hostport = authority[i+1:]
	}
	host, port := hostport, ""
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && !strings.Contains(hostport[i:], "]") {
		host, port = hostport[:i], hostport[i+1:]
		if port == "" {
			return false
		}
	}
	if host != strings.ToLower(host) {
		return false
	}
	def, _ := defaultPort(scheme)
	return port == "" || def != port
}

// normalizedPct reports whether every percent-encoding uses uppercase hex
// digits and none encodes an unreserved character.
func normalizedPct(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		hi, lo := s[i+1], s[i+2]
		if hi != toUpperHex(hi) || lo != toUpperHex(lo) {
			return false
		}
		if isUnreserved(fromHex(hi)<<4 | fromHex(lo)) {
			return false
		}
	}
	return true
}

func toUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

func fromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func validScheme(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func pctAt(s string, i int) bool {
	return i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2])
}

// inIPLiteral reports whether the bracket at s[i] belongs to the host of an
// authority ("//" ... "[" ... "]").
func inIPLiteral(s string, i int) bool {
	if !strings.HasPrefix(s, "//") {
		return false
	}
	end := strings.IndexAny(s[2:], "/?#")
	if end < 0 {
		end = len(s) - 2
	}
	return i < end+2
}

func isURIChar(c byte) bool {
	return isUnreserved(c) || strings.IndexByte(":/?#@!$&'()*+,;=", c) >= 0
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
func isUnreserved(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~'
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
		case strings.HasPrefix(in, "/../"), in == "/..":
			in = "/" + in[min(len(in), 4):]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			j := strings.IndexByte(in[1:], '/')
			if j < 0 {
				out, in = append(out, in), ""
			} else {
				out, in = append(out, in[:j+1]), in[j+1:]
			}
		}
	}
	return strings.Join(out, "")
}
