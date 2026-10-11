package vm

// Shape records how a property whose value may be either one value or a set
// was written: service type and serviceEndpoint (CID 1.0 §2.1.4: "a string
// or a set of strings", "a single string, a single map, or a set") and the
// DID document controller (DID Core 1.0 §5.1.2). Both forms are the same
// data in the data model, but a lossless round trip (docs/00 FR-R4, NFR-1)
// writes back the form that was read, so consumers record it and producers
// follow it.
type Shape int

const (
	// ShapeDefault lets the producer choose: a single value when there is
	// exactly one element and a set otherwise. document.Builder resolves it
	// to ShapeSingle or ShapeSet when it builds a document.
	ShapeDefault Shape = iota
	// ShapeSingle is a single value; the property has exactly one element.
	ShapeSingle
	// ShapeSet is a set (a JSON array), even when it has one element.
	ShapeSet
)

// String returns "default", "single" or "set".
func (s Shape) String() string {
	switch s {
	case ShapeSingle:
		return "single"
	case ShapeSet:
		return "set"
	}
	return "default"
}

// Valid reports whether s is one of the three shapes.
func (s Shape) Valid() bool { return s >= ShapeDefault && s <= ShapeSet }

// Resolve returns the explicit shape for n elements: s itself when it is
// ShapeSingle or ShapeSet, and otherwise ShapeSingle for one element and
// ShapeSet for any other count.
func (s Shape) Resolve(n int) Shape {
	if s == ShapeSingle || s == ShapeSet {
		return s
	}
	if n == 1 {
		return ShapeSingle
	}
	return ShapeSet
}

// CheckShape reports whether shape s can hold n elements of property; it
// returns a *Error naming statement when it cannot.
func CheckShape(property, statement string, s Shape, n int) error {
	if !s.Valid() {
		return errorf(property, statement, "unknown shape %d", int(s))
	}
	if s == ShapeSingle && n != 1 {
		return errorf(property, statement, "a single value holds exactly one element, not %d", n)
	}
	return nil
}
