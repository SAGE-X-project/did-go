package wire

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// IsInteger reports whether number text has no decimal and no fractional
// component, which DID Core 1.0 §6.2.2 and DID 1.1 §6.2.2 consume as an
// integer. Text with a fraction or an exponent is a double: an exponent is
// not a "decimal or fractional component", but "1e3" is not an integer
// lexeme either, and INFRA reads every JSON number as a double, so did-go
// keeps the integer type for plain digit strings only.
func IsInteger(text string) bool {
	return !strings.ContainsAny(text, ".eE")
}

// ToValue converts a JSON value into an INFRA value of the data model by the
// consumption rules of DID Core 1.0 §6.2.2 and DID 1.1 §6.2.2: an object
// becomes a Map in member order, an array a List, a string a String, a
// number an Integer or a Double (IsInteger), a boolean a Boolean and null
// Null. A JSON string is never turned into a DateTime here, because the type
// of an extension entry is unknown ("JSON String, where the data model entry
// value type is string or unknown: A string"). An integer outside the int64
// range or a number that overflows a double is an error rather than a lossy
// conversion.
func ToValue(n Node) (document.Value, error) {
	switch n.Kind {
	case Null:
		return document.Null{}, nil
	case Bool:
		return document.Boolean(n.Bool), nil
	case String:
		return document.String(n.Text), nil
	case Number:
		return numberValue(n.Text)
	case Array:
		items := make([]document.Value, len(n.Items))
		for i, item := range n.Items {
			v, err := ToValue(item)
			if err != nil {
				return nil, err
			}
			items[i] = v
		}
		return document.NewList(items...)
	case Object:
		entries := make([]document.Entry, len(n.Members))
		for i, m := range n.Members {
			v, err := ToValue(m.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.Name, err)
			}
			entries[i] = document.Entry{Key: m.Name, Value: v}
		}
		return document.NewMap(entries...)
	}
	return nil, fmt.Errorf("wire: unknown JSON kind %d", n.Kind)
}

func numberValue(text string) (document.Value, error) {
	if IsInteger(text) {
		i, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wire: integer %s is outside the 64-bit range", text)
		}
		return document.Integer(i), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return nil, fmt.Errorf("wire: number %s does not fit a double", text)
	}
	return document.Double(f), nil
}

// FormatDouble writes f as a JSON number with a decimal and fractional
// component (DID 1.1 §6.2.1: "double: A JSON Number with a decimal and
// fractional component"): the shortest text that reads back as f, with ".0"
// added when that text has no fraction, for example 1.0, 0.5, 1.0e+21.
func FormatDouble(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if strings.ContainsRune(s, '.') {
		return s
	}
	if i := strings.IndexByte(s, 'e'); i >= 0 {
		return s[:i] + ".0" + s[i:]
	}
	return s + ".0"
}

// FromValue converts an INFRA value into JSON by the production rules of
// DID Core 1.0 §6.2.1 and DID 1.1 §6.2.1: a Map becomes an object in entry
// order, a List an array in order, a DateTime a string normalized to UTC
// without sub-second precision (spec.FormatTimestamp), an Integer a number
// without fraction, a Double a number with one (FormatDouble), and String,
// Boolean and Null their JSON forms. The value is checked with
// document.CheckValue first.
func FromValue(v document.Value) (Node, error) {
	if err := document.CheckValue(v); err != nil {
		return Node{}, fmt.Errorf("wire: %w", err)
	}
	return fromValue(v), nil
}

func fromValue(v document.Value) Node {
	switch x := v.(type) {
	case document.String:
		return Node{Kind: String, Text: string(x)}
	case document.Integer:
		return Node{Kind: Number, Text: strconv.FormatInt(int64(x), 10)}
	case document.Double:
		return Node{Kind: Number, Text: FormatDouble(float64(x))}
	case document.Boolean:
		return Node{Kind: Bool, Bool: bool(x)}
	case document.DateTime:
		return Node{Kind: String, Text: spec.FormatTimestamp(x.Time())}
	case document.List:
		items := make([]Node, x.Len())
		for i := range items {
			items[i] = fromValue(x.At(i))
		}
		return Node{Kind: Array, Items: items}
	case document.Map:
		members := make([]Member, 0, x.Len())
		for _, e := range x.Entries() {
			members = append(members, Member{Name: e.Key, Value: fromValue(e.Value)})
		}
		return Node{Kind: Object, Members: members}
	}
	return Node{Kind: Null}
}

// ToAny converts a JSON value into the plain Go form that vm uses for
// additional properties, JSON Web Keys and endpoint maps: nil, bool, string,
// json.Number holding the exact number text, []any and map[string]any.
func ToAny(n Node) any {
	switch n.Kind {
	case Bool:
		return n.Bool
	case String:
		return n.Text
	case Number:
		return json.Number(n.Text)
	case Array:
		out := make([]any, len(n.Items))
		for i, item := range n.Items {
			out[i] = ToAny(item)
		}
		return out
	case Object:
		out := make(map[string]any, len(n.Members))
		for _, m := range n.Members {
			out[m.Name] = ToAny(m.Value)
		}
		return out
	}
	return nil
}

// FromAny converts a plain Go JSON value into a Node. Map keys are written
// in sorted order, because Go maps have none (docs/00 NFR-1). A json.Number
// must be valid number text. Other numbers are written as encoding/json
// writes them. The value is checked with vm.CheckJSONValue first.
func FromAny(v any) (Node, error) {
	if err := vm.CheckJSONValue(v); err != nil {
		return Node{}, fmt.Errorf("wire: %w", err)
	}
	return fromAny(v)
}

func fromAny(v any) (Node, error) {
	switch x := v.(type) {
	case nil:
		return Node{Kind: Null}, nil
	case bool:
		return Node{Kind: Bool, Bool: x}, nil
	case string:
		return Node{Kind: String, Text: x}, nil
	case json.Number:
		if !validNumber(string(x)) {
			return Node{}, fmt.Errorf("wire: %q is not a JSON number", string(x))
		}
		return Node{Kind: Number, Text: string(x)}, nil
	case []any:
		items := make([]Node, len(x))
		for i, item := range x {
			n, err := fromAny(item)
			if err != nil {
				return Node{}, err
			}
			items[i] = n
		}
		return Node{Kind: Array, Items: items}, nil
	case map[string]any:
		return fromMap(x)
	}
	return goNumber(v), nil
}

// fromMap converts a map with its keys sorted.
func fromMap(m map[string]any) (Node, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	members := make([]Member, len(keys))
	for i, k := range keys {
		n, err := fromAny(m[k])
		if err != nil {
			return Node{}, err
		}
		members[i] = Member{Name: k, Value: n}
	}
	return Node{Kind: Object, Members: members}, nil
}

// goNumber converts a Go numeric value, which vm.CheckJSONValue has already
// checked to be a finite number; encoding/json never fails on one.
func goNumber(v any) Node {
	data, _ := json.Marshal(v)
	return Node{Kind: Number, Text: string(data)}
}

// validNumber reports whether text is exactly one RFC 8259 number.
func validNumber(text string) bool {
	if text == "" {
		return false
	}
	p := &parser{data: []byte(text)}
	if _, err := p.number(); err != nil {
		return false
	}
	return p.pos == len(text)
}
