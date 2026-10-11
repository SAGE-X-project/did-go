package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
)

func TestDriver(t *testing.T) {
	d := &Driver{Method: "example", Media: []string{"application/did"}, Func: Static("{}", "application/did", document.Metadata{VersionID: "1"})}
	if d.Name() != "example" || d.Produces()[0] != "application/did" {
		t.Fatal("name or media")
	}
	rr, err := d.Read(context.Background(), MustDID("did:example:1"), method.ReadOptions{VersionID: "x"})
	if err != nil || string(rr.Data) != "{}" || rr.Metadata.VersionID != "1" || d.Calls()[0].VersionID != "x" {
		t.Fatal("Read")
	}
	if _, err := Fail(method.ErrNotFound)(context.Background(), MustDID("did:example:1"), method.ReadOptions{}); !errors.Is(err, method.ErrNotFound) {
		t.Fatal("Fail")
	}
	for _, err := range []error{
		func() error { _, e := d.Create(context.Background(), nil, method.CreateOptions{}); return e }(),
		func() error {
			_, e := d.Update(context.Background(), MustDID("did:example:1"), nil, method.UpdateOptions{})
			return e
		}(),
		func() error {
			_, e := d.Deactivate(context.Background(), MustDID("did:example:1"), method.DeactivateOptions{})
			return e
		}(),
	} {
		if !errors.Is(err, method.ErrNotSupported) {
			t.Fatal("unsupported operation")
		}
	}
	if MustURL("did:example:1#a").Fragment() != "a" {
		t.Fatal("MustURL")
	}
	for _, f := range []func(){func() { MustDID("x") }, func() { MustURL("x") }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			f()
		}()
	}
}
