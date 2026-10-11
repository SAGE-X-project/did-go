// Package wire is the JSON tool shared by the producer and consumer players
// (docs/14 §2): a strict JSON parser with input limits, a deterministic
// encoder, the conversion between JSON and INFRA values of the DID document
// data model (DID Core 1.0 §6.2, DID 1.1 §6.2), and the table of property
// names.
//
// The parser follows RFC 8259 and the security rules of docs/12 §6.3: it
// rejects invalid UTF-8 (including escaped lone surrogates), duplicate object
// members, input larger than Limits.MaxBytes and nesting deeper than
// Limits.MaxDepth. It keeps member order and the exact text of numbers.
package wire

import (
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Default input limits (docs/12 §6.3). A DID document is small: did:key
// documents are below 2 KiB and did:web documents rarely exceed a few
// kilobytes, so 1 MiB is generous while bounding memory. The depth limit is
// above every depth the data model allows (64 levels of value nesting below
// an entry, document.CheckValue and vm.CheckJSONValue, plus at most four
// levels of document structure), so anything the producer writes the
// consumer can read.
const (
	DefaultMaxBytes = 1 << 20
	DefaultMaxDepth = 100
)

// Limits bound the input of Parse. A zero field takes its default.
type Limits struct {
	// MaxBytes is the largest accepted input, in bytes.
	MaxBytes int
	// MaxDepth is the deepest accepted nesting of arrays and objects; the
	// root value is at depth 1.
	MaxDepth int
}

// withDefaults fills zero fields.
func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	return l
}

// Kind is the JSON type of a Node.
type Kind uint8

// JSON types.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// String returns the RFC 8259 name of the type.
func (k Kind) String() string {
	switch k {
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "null"
}

// Node is a parsed JSON value. Text holds a string's value or a number's
// exact text; Items holds array elements; Members holds object members in
// input order.
type Node struct {
	Kind    Kind
	Bool    bool
	Text    string
	Items   []Node
	Members []Member
}

// Member is one name and value of an object.
type Member struct {
	Name  string
	Value Node
}

// Get returns the value of the member called name.
func (n Node) Get(name string) (Node, bool) {
	for _, m := range n.Members {
		if m.Name == name {
			return m.Value, true
		}
	}
	return Node{}, false
}

// Error reports input that Parse rejects, at a byte offset.
type Error struct {
	Offset int
	Reason string
}

// Error describes the failure without echoing the input (docs/12 §6.3).
func (e *Error) Error() string {
	return fmt.Sprintf("wire: offset %d: %s", e.Offset, e.Reason)
}

type parser struct {
	data  []byte
	pos   int
	depth int
	lim   Limits
}

func (p *parser) fail(format string, args ...any) error {
	return &Error{Offset: p.pos, Reason: fmt.Sprintf(format, args...)}
}

// Parse parses one JSON text. Whitespace may surround the value; anything
// else after it is an error.
func Parse(data []byte, lim Limits) (Node, error) {
	lim = lim.withDefaults()
	if len(data) > lim.MaxBytes {
		return Node{}, &Error{Offset: lim.MaxBytes, Reason: fmt.Sprintf("input larger than %d bytes", lim.MaxBytes)}
	}
	if !utf8.Valid(data) {
		return Node{}, &Error{Offset: invalidUTF8At(data), Reason: "input is not valid UTF-8"}
	}
	p := &parser{data: data, lim: lim}
	p.skipSpace()
	n, err := p.value()
	if err != nil {
		return Node{}, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return Node{}, p.fail("data after the JSON value")
	}
	return n, nil
}

func invalidUTF8At(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(data)
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value() (Node, error) {
	if p.pos >= len(p.data) {
		return Node{}, p.fail("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		return Node{Kind: String, Text: s}, err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return p.literal()
	}
}

func (p *parser) literal() (Node, error) {
	for _, lit := range []struct {
		text string
		node Node
	}{{"true", Node{Kind: Bool, Bool: true}}, {"false", Node{Kind: Bool}}, {"null", Node{Kind: Null}}} {
		if len(p.data)-p.pos >= len(lit.text) && string(p.data[p.pos:p.pos+len(lit.text)]) == lit.text {
			p.pos += len(lit.text)
			return lit.node, nil
		}
	}
	return Node{}, p.fail("invalid character %q", p.data[p.pos])
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > p.lim.MaxDepth {
		return p.fail("nesting deeper than %d levels", p.lim.MaxDepth)
	}
	p.pos++
	p.skipSpace()
	return nil
}

func (p *parser) object() (Node, error) {
	if err := p.enter(); err != nil {
		return Node{}, err
	}
	n := Node{Kind: Object, Members: []Member{}}
	seen := map[string]bool{}
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		p.depth--
		return n, nil
	}
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return Node{}, p.fail("expected a member name")
		}
		at := p.pos
		name, err := p.str()
		if err != nil {
			return Node{}, err
		}
		if seen[name] {
			return Node{}, &Error{Offset: at, Reason: fmt.Sprintf("duplicate member %q", name)}
		}
		seen[name] = true
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return Node{}, p.fail("expected ':'")
		}
		p.pos++
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return Node{}, err
		}
		n.Members = append(n.Members, Member{Name: name, Value: v})
		if done, err := p.next('}'); done || err != nil {
			return n, err
		}
	}
}

func (p *parser) array() (Node, error) {
	if err := p.enter(); err != nil {
		return Node{}, err
	}
	n := Node{Kind: Array, Items: []Node{}}
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		p.depth--
		return n, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return Node{}, err
		}
		n.Items = append(n.Items, v)
		if done, err := p.next(']'); done || err != nil {
			return n, err
		}
	}
}

// next consumes a ',' (false) or the closing byte (true).
func (p *parser) next(closing byte) (bool, error) {
	p.skipSpace()
	if p.pos >= len(p.data) {
		return false, p.fail("unexpected end of input")
	}
	switch p.data[p.pos] {
	case ',':
		p.pos++
		p.skipSpace()
		return false, nil
	case closing:
		p.pos++
		p.depth--
		return true, nil
	}
	return false, p.fail("expected ',' or %q", closing)
}

func (p *parser) number() (Node, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case p.pos < len(p.data) && p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		p.digits()
	default:
		return Node{}, p.fail("invalid number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.digits() == 0 {
			return Node{}, p.fail("invalid number: no digit after '.'")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.digits() == 0 {
			return Node{}, p.fail("invalid number: no digit in exponent")
		}
	}
	return Node{Kind: Number, Text: string(p.data[start:p.pos])}, nil
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

// str parses a string starting at the opening quote.
func (p *parser) str() (string, error) {
	p.pos++
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
		case c < 0x20:
			return "", p.fail("control character in string")
		default:
			out = append(out, c)
			p.pos++
		}
	}
}

// escape parses an escape sequence at a backslash and returns its rune. A
// \u escape of a surrogate must be a valid pair; a lone surrogate has no
// UTF-8 form and is rejected.
func (p *parser) escape() (rune, error) {
	if p.pos+1 >= len(p.data) {
		return 0, p.fail("unterminated escape")
	}
	c := p.data[p.pos+1]
	p.pos += 2
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		return p.unicodeEscape()
	}
	p.pos -= 2
	return 0, p.fail("invalid escape \\%c", c)
}

func (p *parser) unicodeEscape() (rune, error) {
	r, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if !utf16.IsSurrogate(r) {
		return r, nil
	}
	if r >= 0xDC00 || p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
		return 0, p.fail("lone surrogate in \\u escape")
	}
	p.pos += 2
	lo, err := p.hex4()
	if err != nil {
		return 0, err
	}
	pair := utf16.DecodeRune(r, lo)
	if pair == utf8.RuneError {
		return 0, p.fail("lone surrogate in \\u escape")
	}
	return pair, nil
}

func (p *parser) hex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.fail("short \\u escape")
	}
	v, err := strconv.ParseUint(string(p.data[p.pos:p.pos+4]), 16, 16)
	if err != nil {
		return 0, p.fail("invalid \\u escape")
	}
	p.pos += 4
	return rune(v), nil
}
