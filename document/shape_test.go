package document

import (
	"testing"

	"github.com/sage-x-project/did-go/vm"
)

func TestControllerShape(t *testing.T) {
	a, b := mustDID(t, "did:example:a"), mustDID(t, "did:example:b")
	t.Run("absent controller has the default shape", func(t *testing.T) {
		if s := build(t, builder(t)).ControllerShape(); s != vm.ShapeDefault {
			t.Fatalf("shape %s", s)
		}
	})
	t.Run("core10#did-controller.2 the default is a string for one DID and a set for more", func(t *testing.T) {
		if s := build(t, builder(t).Controller(a)).ControllerShape(); s != vm.ShapeSingle {
			t.Fatalf("one controller: %s", s)
		}
		if s := build(t, builder(t).Controller(a, b)).ControllerShape(); s != vm.ShapeSet {
			t.Fatalf("two controllers: %s", s)
		}
	})
	t.Run("core10#did-controller.2 a set of one DID and the empty set are kept", func(t *testing.T) {
		if s := build(t, builder(t).Controller(a).ControllerShape(vm.ShapeSet)).ControllerShape(); s != vm.ShapeSet {
			t.Fatalf("set of one: %s", s)
		}
		d := build(t, builder(t).ControllerShape(vm.ShapeSet))
		if d.ControllerShape() != vm.ShapeSet || d.Controllers() != nil {
			t.Fatal("empty set")
		}
		if s := build(t, NewBuilderFrom(d)).ControllerShape(); s != vm.ShapeSet {
			t.Fatal("NewBuilderFrom must keep the shape")
		}
	})
	t.Run("core10#did-controller.2 a single string holds exactly one DID", func(t *testing.T) {
		wantBuildError(t, builder(t).Controller(a, b).ControllerShape(vm.ShapeSingle), "core10#did-controller.2")
		wantBuildError(t, builder(t).ControllerShape(vm.ShapeSingle), "core10#did-controller.2")
		wantBuildError(t, builder(t).Controller(a).ControllerShape(vm.Shape(5)), "core10#did-controller.2")
	})
}

func TestServiceShapeResolved(t *testing.T) {
	ep := vm.Endpoint{URL: "https://example.com/"}
	t.Run("cid10#services.9 Build resolves the default type and endpoint shapes", func(t *testing.T) {
		d := build(t, builder(t).Service(
			vm.Service{ID: "#a", Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{ep}},
			vm.Service{ID: "#b", Type: []string{"A", "B"}, ServiceEndpoint: []vm.Endpoint{ep, {URL: "https://b.example/"}}},
			vm.Service{ID: "#c", Type: []string{"A"}, TypeShape: vm.ShapeSet, ServiceEndpoint: []vm.Endpoint{ep}, EndpointShape: vm.ShapeSet},
		))
		got := d.Services()
		want := [][2]vm.Shape{{vm.ShapeSingle, vm.ShapeSingle}, {vm.ShapeSet, vm.ShapeSet}, {vm.ShapeSet, vm.ShapeSet}}
		for i, w := range want {
			if got[i].TypeShape != w[0] || got[i].EndpointShape != w[1] {
				t.Errorf("service %d: %s %s", i, got[i].TypeShape, got[i].EndpointShape)
			}
		}
	})
	t.Run("cid10#services.12 a single endpoint shape with two endpoints is rejected", func(t *testing.T) {
		bad := vm.Service{Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{ep, ep}, EndpointShape: vm.ShapeSingle}
		wantBuildError(t, builder(t).Service(bad), "cid10#services.12")
	})
}
