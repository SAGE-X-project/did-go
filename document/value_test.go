package document

import (
	"math"
	"testing"
	"time"
)

func TestValues(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	l, err := NewList(String("a"), Integer(1), Double(1.5), Boolean(true), Null{}, NewDateTime(now))
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 6 || l.At(0) != String("a") || !l.At(5).(DateTime).Time().Equal(now) {
		t.Fatal("list")
	}
	items := l.Items()
	items[0] = String("b")
	if l.At(0) != String("a") {
		t.Fatal("Items must return a copy")
	}
	if _, err := NewList(nil); err == nil {
		t.Fatal("nil element accepted")
	}
	m, err := NewMap(Entry{"a", l}, Entry{"b", String("x")})
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 2 || m.Keys()[1] != "b" || len(m.Entries()) != 2 {
		t.Fatal("map")
	}
	m2, err := m.With("c", Integer(3))
	if err != nil || m.Len() != 2 || m2.Len() != 3 {
		t.Fatal("With must not change the receiver")
	}
	if _, ok := m.Get("zz"); ok {
		t.Fatal("missing key found")
	}
	if _, err := NewMap(Entry{"a", Null{}}, Entry{"a", Null{}}); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := m.With("d", nil); err == nil {
		t.Fatal("nil value accepted")
	}
	if err := CheckValue(m2); err != nil {
		t.Fatal(err)
	}
	deep := Value(String("x"))
	for i := 0; i < 70; i++ {
		deep, _ = NewList(deep)
	}
	badMap, _ := NewMap(Entry{"\xff", Null{}})
	nested, _ := NewMap(Entry{"k", Double(math.Inf(1))})
	nestedList, _ := NewList(String("\xff"))
	for _, bad := range []Value{Double(math.NaN()), String("\xff"), NewDateTime(time.Time{}), NewDateTime(time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)), deep, badMap, nested, nestedList, nil} {
		if CheckValue(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
