package vm

import "testing"

func TestShape(t *testing.T) {
	for s, want := range map[Shape]string{ShapeDefault: "default", ShapeSingle: "single", ShapeSet: "set", Shape(9): "default"} {
		if s.String() != want {
			t.Errorf("%d.String() = %q", int(s), s.String())
		}
	}
	if Shape(9).Valid() || Shape(-1).Valid() || !ShapeSet.Valid() {
		t.Fatal("Valid")
	}
	for _, c := range []struct {
		s    Shape
		n    int
		want Shape
	}{
		{ShapeDefault, 1, ShapeSingle}, {ShapeDefault, 2, ShapeSet}, {ShapeDefault, 0, ShapeSet},
		{ShapeSet, 1, ShapeSet}, {ShapeSingle, 1, ShapeSingle},
	} {
		if got := c.s.Resolve(c.n); got != c.want {
			t.Errorf("%s.Resolve(%d) = %s", c.s, c.n, got)
		}
	}
}

func TestServiceShape(t *testing.T) {
	web := Endpoint{URL: "https://example.com/"}
	t.Run("cid10#services.9 a single type string has exactly one element", func(t *testing.T) {
		s := svc("", web)
		s.TypeShape = ShapeSingle
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		s.TypeShape = ShapeSet
		if err := s.Validate(); err != nil {
			t.Fatal("a set of one type is valid:", err)
		}
		s.Type, s.TypeShape = []string{"A", "B"}, ShapeSingle
		wantStatement(t, s.Validate(), "cid10#services.9")
		s.TypeShape = Shape(7)
		wantStatement(t, s.Validate(), "cid10#services.9")
	})
	t.Run("cid10#services.12 a single endpoint is one string or one map", func(t *testing.T) {
		s := svc("", web, web)
		s.EndpointShape = ShapeSet
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		s.EndpointShape = ShapeSingle
		wantStatement(t, s.Validate(), "cid10#services.12")
		one := svc("", web)
		one.EndpointShape = ShapeSingle
		if err := one.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Clone keeps the shapes", func(t *testing.T) {
		s := svc("", web)
		s.TypeShape, s.EndpointShape = ShapeSet, ShapeSingle
		c := s.Clone()
		if c.TypeShape != ShapeSet || c.EndpointShape != ShapeSingle {
			t.Fatal("shapes lost")
		}
	})
}
