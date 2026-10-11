package wire

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
)

func method(t *testing.T) vm.Method {
	t.Helper()
	id, err := did.ParseReference("did:example:123#k")
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := did.Parse("did:example:123")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	return vm.Method{ID: id, Type: "JsonWebKey", Controller: ctl, Expires: &at, Revoked: &at,
		PublicKeyMultibase: "zPub", PublicKeyJwk: map[string]any{"kty": "OKP"},
		SecretKeyMultibase: "zSec", SecretKeyJwk: map[string]any{"d": "x"},
		Extra: map[string]any{"b": true, "a": "x"}}
}

func TestFromMethod(t *testing.T) {
	m := method(t)
	n, err := FromMethod(m, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"did:example:123#k","type":"JsonWebKey","controller":"did:example:123","expires":"2030-01-02T03:04:05Z",` +
		`"revoked":"2030-01-02T03:04:05Z","publicKeyMultibase":"zPub","publicKeyJwk":{"kty":"OKP"},"a":"x","b":true}`
	if got := string(Encode(n)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	n, err = FromMethod(m, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(Encode(n)); !strings.Contains(got, `"secretKeyMultibase":"zSec","secretKeyJwk":{"d":"x"}`) {
		t.Fatal(got)
	}
	for name, bad := range map[string]vm.Method{
		"publicKeyJwk": {PublicKeyJwk: map[string]any{"x": make(chan int)}},
		"secretKeyJwk": {SecretKeyJwk: map[string]any{"x": make(chan int)}},
		"z":            {Extra: map[string]any{"z": make(chan int)}},
	} {
		_, err := FromMethod(bad, true)
		var pe *PropertyError
		if !errors.As(err, &pe) || pe.Property != name || errors.Unwrap(err) == nil || !strings.Contains(err.Error(), "wire: "+name+": ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFromService(t *testing.T) {
	s := vm.Service{ID: "#s", Type: []string{"A"}, TypeShape: vm.ShapeSingle,
		ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}, {Map: map[string]any{"uri": "https://f.example/"}}},
		Extra:           map[string]any{"x": 1}}
	n, err := FromService(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"#s","type":"A","serviceEndpoint":["https://e.example/",{"uri":"https://f.example/"}],"x":1}`
	if got := string(Encode(n)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	n, _ = FromService(vm.Service{Type: []string{"A"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://e.example/"}}, EndpointShape: vm.ShapeSet})
	if got := string(Encode(n)); got != `{"type":"A","serviceEndpoint":["https://e.example/"]}` {
		t.Fatal(got)
	}
	for name, bad := range map[string]vm.Service{
		"serviceEndpoint[0]": {ServiceEndpoint: []vm.Endpoint{{Map: map[string]any{"x": make(chan int)}}}},
		"y":                  {Extra: map[string]any{"y": make(chan int)}},
	} {
		var pe *PropertyError
		if _, err := FromService(bad); !errors.As(err, &pe) || pe.Property != name {
			t.Errorf("%s: %v", name, err)
		}
	}
}
