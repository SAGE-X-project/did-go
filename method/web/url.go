package web

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-go/did"
)

// Requirement ids of the did:web specification used in errors.
const (
	stmtMethodName  = "didweb-ea423c1#method-name.1"
	stmtNoIP        = "didweb-ea423c1#method-specific-identifier.1"
	stmtPort        = "didweb-ea423c1#method-specific-identifier.2"
	stmtPath        = "didweb-ea423c1#method-specific-identifier.3"
	stmtCreatePort  = "didweb-ea423c1#create-register.1"
	stmtGet         = "didweb-ea423c1#read-resolve.7"
	stmtVerifyID    = "didweb-ea423c1#read-resolve.8"
	sectionKeys     = "didweb-ea423c1 §key-material-and-document-handling"
	sectionSecurity = "didweb-ea423c1 §security-and-privacy-considerations"
)

const (
	wellKnown    = "/.well-known"
	documentName = "/did.json"
	defaultPort  = "443"
	maxHostLen   = 253
	maxLabelLen  = 63
)

// URL returns the HTTPS URL of the DID document of d by steps 1 to 5 of the
// Read (Resolve) algorithm: the colons of the method-specific identifier
// become slashes, a percent-encoded port colon is decoded, https:// is
// prepended, /.well-known is appended when there is no path, and /did.json
// completes the URL.
//
// The domain must be a DNS name, not an IP address, with an optional port
// whose colon is percent-encoded. Path segments must be non-empty and must
// not decode to "." or "..", or contain "/", "\", "?", "#" or control
// characters, so that no DID names a document outside its own path.
func URL(d did.DID) (*url.URL, error) {
	if d.Method() != Name {
		return nil, raise(CodeInvalidDid, stmtMethodName, "method %q is not %q", d.Method(), Name)
	}
	segments := strings.Split(d.MSID(), ":")
	host, err := parseDomain(segments[0])
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	sb.WriteString("https://")
	sb.WriteString(host)
	if len(segments) == 1 {
		sb.WriteString(wellKnown)
	}
	for _, seg := range segments[1:] {
		if err := checkSegment(seg, CodeInvalidDid); err != nil {
			return nil, err
		}
		sb.WriteByte('/')
		sb.WriteString(seg)
	}
	sb.WriteString(documentName)
	u, err := url.Parse(sb.String())
	if err != nil {
		return nil, wrap(CodeInvalidDid, stmtPath, err, "the DID does not form a URL")
	}
	return u, nil
}

// parseDomain checks the first segment of the method-specific identifier and
// returns host[:port] with the port colon decoded.
func parseDomain(seg string) (string, error) {
	name, port := seg, ""
	if i := strings.Index(strings.ToUpper(seg), "%3A"); i >= 0 {
		name, port = seg[:i], seg[i+3:]
		if err := checkPort(port, stmtPort, CodeInvalidDid); err != nil {
			return "", err
		}
	}
	if strings.Contains(name, "%") {
		return "", raise(CodeInvalidDid, stmtNoIP, "the domain %q contains a percent-encoded octet other than the port colon", name)
	}
	if err := checkHost(name, CodeInvalidDid); err != nil {
		return "", err
	}
	if port == "" {
		return name, nil
	}
	return name + ":" + port, nil
}

func checkPort(port, statement, code string) error {
	n, err := strconv.Atoi(port)
	if err != nil || port == "" || len(port) > 5 || strings.TrimLeft(port, "0123456789") != "" || n < 1 || n > 65535 {
		return raise(code, statement, "%q is not a port number", port)
	}
	return nil
}

// checkHost requires a DNS name (RFC 1035, RFC 1123): labels of letters,
// digits and hyphens, 1 to 63 octets, not starting or ending with a hyphen,
// at most 253 octets in all. An IP address is refused, and so is a name whose
// last label is all digits, because such a name is read as an IPv4 address
// in numeric forms like "127.1" by some resolvers (RFC 3696 §2: top-level
// domains are never all-numeric).
func checkHost(name, code string) error {
	if net.ParseIP(name) != nil {
		return raise(code, stmtNoIP, "the domain %q is an IP address", name)
	}
	if name == "" || len(name) > maxHostLen {
		return raise(code, stmtNoIP, "the domain %q is not a DNS name", name)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if !isLabel(l) {
			return raise(code, stmtNoIP, "the domain %q is not a DNS name", name)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return raise(code, stmtNoIP, "the domain %q ends with a numeric label and may be read as an IP address", name)
	}
	return nil
}

func isLabel(l string) bool {
	if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// checkSegment checks one path segment of the method-specific identifier.
func checkSegment(seg, code string) error {
	if seg == "" {
		return raise(code, stmtPath, "empty path segment")
	}
	dec, err := url.PathUnescape(seg)
	if err != nil {
		return wrap(code, stmtPath, err, "path segment %q is not percent-encoded correctly", seg)
	}
	if dec == "." || dec == ".." {
		return raise(code, stmtPath, "path segment %q is a dot segment", seg)
	}
	for i := 0; i < len(dec); i++ {
		c := dec[i]
		if c == '/' || c == '\\' || c == '?' || c == '#' || c < 0x20 || c == 0x7f {
			return raise(code, stmtPath, "path segment %q decodes to a character that changes the URL structure", seg)
		}
	}
	return nil
}

// DIDFromURL returns the did:web DID whose document is served at rawURL, the
// inverse of URL. It helps a DID controller name the DID of a did.json file
// it hosts (Create (Register)): https://example.com/.well-known/did.json is
// did:web:example.com, https://example.com:3000/user/alice/did.json is
// did:web:example.com%3A3000:user:alice. The port colon is percent-encoded
// (create-register.1), and port 443 is dropped. The URL must use https, name
// a DNS host, end with /did.json and carry no user information, query or
// fragment. Octets of a path segment that a DID cannot carry are
// percent-encoded; the host is written in lowercase.
func DIDFromURL(rawURL string) (did.DID, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return did.DID{}, wrap(CodeInvalidURL, stmtCreatePort, err, "not a URL")
	}
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return did.DID{}, raise(CodeInvalidURL, stmtGet, "only an https URL without user information, query or fragment names a did:web document")
	}
	host := strings.ToLower(u.Hostname())
	if err := checkHost(host, CodeInvalidURL); err != nil {
		return did.DID{}, err
	}
	msid := host
	if p := u.Port(); p != "" && p != defaultPort {
		if err := checkPort(p, stmtCreatePort, CodeInvalidURL); err != nil {
			return did.DID{}, err
		}
		msid += "%3A" + p
	}
	path := u.EscapedPath()
	dir, ok := strings.CutSuffix(path, documentName)
	if !ok || dir == "" {
		return did.DID{}, raise(CodeInvalidURL, stmtPath, "the path %q does not end with a directory and /did.json", path)
	}
	if dir != wellKnown {
		for _, seg := range strings.Split(dir[1:], "/") {
			enc, err := encodeSegment(seg)
			if err != nil {
				return did.DID{}, err
			}
			msid += ":" + enc
		}
	}
	d, err := did.Parse("did:" + Name + ":" + msid)
	if err != nil {
		return did.DID{}, wrap(CodeInvalidURL, stmtPath, err, "the URL does not form a DID")
	}
	return d, nil
}

// encodeSegment decodes a URL path segment and percent-encodes every octet
// that is not a DID idchar (ALPHA, DIGIT, ".", "-", "_").
func encodeSegment(seg string) (string, error) {
	if err := checkSegment(seg, CodeInvalidURL); err != nil {
		return "", err
	}
	dec, _ := url.PathUnescape(seg)
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(dec); i++ {
		c := dec[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0x0f])
	}
	return sb.String(), nil
}
