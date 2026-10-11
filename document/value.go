package document

import (
	"fmt"
	"math"
	"slices"
	"time"
	"unicode/utf8"
)

// Value is a value of the DID document data model (DID Core 1.0 §4, INFRA):
// String, Integer, Double, Boolean, Null, DateTime, List or Map. Every Value
// is immutable.
type Value interface {
	infraValue()
}

// String is an INFRA string.
type String string

// Integer is an integer number without fractional part.
type Integer int64

// Double is a finite floating point number.
type Double float64

// Boolean is an INFRA boolean.
type Boolean bool

// Null is the INFRA null value.
type Null struct{}

// DateTime is a point in time; representations write it in UTC.
type DateTime struct{ t time.Time }

// NewDateTime returns t as a DateTime.
func NewDateTime(t time.Time) DateTime { return DateTime{t: t} }

// Time returns the time.
func (d DateTime) Time() time.Time { return d.t }

// List is an ordered list of values.
type List struct{ items []Value }

// NewList returns a list of the given values. A nil element is an error.
func NewList(items ...Value) (List, error) {
	for i, v := range items {
		if v == nil {
			return List{}, fmt.Errorf("document: list element %d is nil", i)
		}
	}
	return List{items: slices.Clone(items)}, nil
}

// Len returns the number of elements.
func (l List) Len() int { return len(l.items) }

// At returns element i.
func (l List) At(i int) Value { return l.items[i] }

// Items returns the elements in a fresh slice.
func (l List) Items() []Value { return slices.Clone(l.items) }

// Entry is one key and value of a Map.
type Entry struct {
	Key   string
	Value Value
}

// Map is an ordered map with string keys and no duplicate keys. The zero
// value is an empty map.
type Map struct{ entries []Entry }

// NewMap returns a map of the given entries in order. A duplicate key or a
// nil value is an error.
func NewMap(entries ...Entry) (Map, error) {
	var m Map
	for _, e := range entries {
		next, err := m.With(e.Key, e.Value)
		if err != nil {
			return Map{}, err
		}
		m = next
	}
	return m, nil
}

// With returns a new map with key added at the end. The receiver does not
// change. An existing key or a nil value is an error.
func (m Map) With(key string, v Value) (Map, error) {
	if v == nil {
		return Map{}, fmt.Errorf("document: value of %q is nil", key)
	}
	if _, ok := m.Get(key); ok {
		return Map{}, fmt.Errorf("document: duplicate key %q", key)
	}
	out := make([]Entry, len(m.entries), len(m.entries)+1)
	copy(out, m.entries)
	return Map{entries: append(out, Entry{key, v})}, nil
}

// Get returns the value of key.
func (m Map) Get(key string) (Value, bool) {
	for _, e := range m.entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

// Len returns the number of entries.
func (m Map) Len() int { return len(m.entries) }

// Keys returns the keys in order, in a fresh slice.
func (m Map) Keys() []string {
	out := make([]string, len(m.entries))
	for i, e := range m.entries {
		out[i] = e.Key
	}
	return out
}

// Entries returns the entries in order, in a fresh slice.
func (m Map) Entries() []Entry { return slices.Clone(m.entries) }

func (String) infraValue()   {}
func (Integer) infraValue()  {}
func (Double) infraValue()   {}
func (Boolean) infraValue()  {}
func (Null) infraValue()     {}
func (DateTime) infraValue() {}
func (List) infraValue()     {}
func (Map) infraValue()      {}

// maxValueDepth bounds the nesting of values (docs/12 §6.3).
const maxValueDepth = 64

// CheckValue reports whether v can be represented: strings are valid UTF-8,
// doubles are finite, datetimes have a four-digit year, and nesting is at
// most 64 levels.
func CheckValue(v Value) error {
	return checkValue(v, 0)
}

func checkValue(v Value, depth int) error {
	if depth > maxValueDepth {
		return fmt.Errorf("value nested deeper than %d levels", maxValueDepth)
	}
	switch x := v.(type) {
	case String:
		if !utf8.ValidString(string(x)) {
			return fmt.Errorf("string is not valid UTF-8")
		}
	case Double:
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return fmt.Errorf("double is not finite")
		}
	case DateTime:
		if y := x.t.UTC().Year(); x.t.IsZero() || y < 1 || y > 9999 {
			return fmt.Errorf("datetime cannot be written with a four-digit year")
		}
	case List:
		for _, e := range x.items {
			if err := checkValue(e, depth+1); err != nil {
				return err
			}
		}
	case Map:
		for _, e := range x.entries {
			if !utf8.ValidString(e.Key) {
				return fmt.Errorf("key is not valid UTF-8")
			}
			if err := checkValue(e.Value, depth+1); err != nil {
				return fmt.Errorf("%s: %w", e.Key, err)
			}
		}
	case nil:
		return fmt.Errorf("nil value")
	}
	return nil
}
