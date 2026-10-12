package sage

import (
	"errors"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
)

func newDriver(t *testing.T, src Source) *Driver {
	t.Helper()
	d, err := NewDriver(src, producer.New())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDriverRead(t *testing.T) {
	r := activeRecord(t)
	d := newDriver(t, newSource(r))
	if d.Name() != "sage" || len(d.Produces()) != 2 || d.Produces()[0] != MediaTypeCore10 {
		t.Fatalf("driver identity %s %v", d.Name(), d.Produces())
	}
	// DIDP-01 and DG-5: each media type gets its projection from the record;
	// no media type means the DID Core 1.0 default (OPEN-2).
	for mt, want := range map[string]string{"": MediaTypeCore10, MediaTypeCore10: MediaTypeCore10, MediaTypeDID11: MediaTypeDID11} {
		rr, err := d.Read(t.Context(), r.DID, method.ReadOptions{MediaType: mt})
		if err != nil || rr.ContentType != want || rr.Metadata.VersionID != "7" {
			t.Fatalf("Read(%q): %v %+v", mt, err, rr)
		}
		p, _ := projectionOf(want)
		if string(rr.Data) != produce(t, r, p) {
			t.Errorf("Read(%q) bytes %s", mt, rr.Data)
		}
	}
}

// DIDP-05: a deactivated record returns no document and deactivated true.
func TestDriverDeactivated(t *testing.T) {
	r := activeRecord(t)
	r.State = StateDeactivated
	rr, err := newDriver(t, newSource(r)).Read(t.Context(), r.DID, method.ReadOptions{})
	if err != nil || rr.Data != nil || !rr.Metadata.Deactivated {
		t.Errorf("deactivated: %v %+v", err, rr)
	}
}

// RESOLVE-02: historical resolution is not offered here; writes go through a
// SAGE registry.
func TestDriverNotSupported(t *testing.T) {
	r := activeRecord(t)
	d := newDriver(t, newSource(r))
	now := time.Now()
	for _, o := range []method.ReadOptions{{VersionID: "1"}, {VersionTime: &now}} {
		if _, err := d.Read(t.Context(), r.DID, o); !errors.Is(err, method.ErrNotSupported) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	if _, err := d.Create(t.Context(), nil, method.CreateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error(err)
	}
	if _, err := d.Update(t.Context(), r.DID, nil, method.UpdateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error(err)
	}
	if _, err := d.Deactivate(t.Context(), r.DID, method.DeactivateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error(err)
	}
	if _, err := NewDriver(nil, producer.New()); err == nil {
		t.Error("nil source accepted")
	}
	if _, err := NewDriver(newSource(), nil); err == nil {
		t.Error("nil producer accepted")
	}
}

// A driver error carries the SAGE error and the method error a standard
// resolver maps.
func TestDriverErrors(t *testing.T) {
	r := activeRecord(t)
	src := newSource(r)
	d := newDriver(t, src)
	cases := map[Code]error{
		CodeRecordNotFound: method.ErrNotFound,
		CodeIDMalformed:    method.ErrInvalidInput,
		CodeSizeExceeded:   method.ErrInvalidInput,
		CodeRecordStale:    nil,
	}
	for code, sentinel := range cases {
		src.errs[r.DID.String()] = NewError(code, "")
		_, err := d.Read(t.Context(), r.DID, method.ReadOptions{})
		var se *Error
		if !errors.As(err, &se) || se.Code != code {
			t.Errorf("%s: %v", code, err)
		}
		if sentinel != nil && !errors.Is(err, sentinel) {
			t.Errorf("%s does not map to %v", code, sentinel)
		}
		if sentinel == nil && (errors.Is(err, method.ErrNotFound) || errors.Is(err, method.ErrInvalidInput)) {
			t.Errorf("%s maps to a specific method error", code)
		}
		if err.Error() != se.Error() {
			t.Errorf("error text %q", err)
		}
	}
	delete(src.errs, r.DID.String())
	other := mustDID(t, "did:sage:web:registry.example:agent-2")
	src.records[other.String()] = r
	if _, err := d.Read(t.Context(), other, method.ReadOptions{}); !errors.Is(err, NewError(CodeRecordInvalid, "")) {
		t.Errorf("record of another identifier: %v", err)
	}
	bad := activeRecord(t)
	bad.Version = "0"
	if _, err := newDriver(t, newSource(bad)).Read(t.Context(), bad.DID, method.ReadOptions{}); !errors.Is(err, NewError(CodeRecordInvalid, "")) {
		t.Errorf("invalid record: %v", err)
	}
}
