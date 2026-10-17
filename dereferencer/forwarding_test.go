package dereferencer_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/resolution"
)

func TestForwardedDereferenceOptions(t *testing.T) {
	for _, accept := range []string{"application/did", "text/uri-list", "image/png"} {
		t.Run(accept, func(t *testing.T) {
			e := newEnv(t)
			opts := resolution.DereferenceOptions{Accept: accept}
			res := e.deref(t, testutil.ExampleDID+"?service=files&versionId=1&versionTime=2021-05-01T00:00:00Z&relativeRef=%2Freport", opts)
			if len(e.spy.calls) != 1 {
				t.Fatalf("nested calls: %d", len(e.spy.calls))
			}
			got := e.spy.calls[0]
			if got.Accept != accept || got.VersionID != "1" || got.VersionTime == nil || !got.VersionTime.Equal(time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)) || !reflect.DeepEqual(got.Extra, map[string]any{"service": "files", "relativeRef": "/report"}) {
				t.Fatalf("forwarded: %+v", got)
			}
			if opts.Accept != accept {
				t.Fatal("original options changed")
			}
			switch accept {
			case "text/uri-list":
				wantSuccess(t, res)
				urls, ok := res.ContentStream.([]string)
				if !ok || !reflect.DeepEqual(urls, []string{"https://files.example/report", "https://files.example/report"}) || res.DereferencingMetadata.ContentType != dereferencer.MediaTypeURIList {
					t.Fatalf("URI list: %+v", res)
				}
			case "application/did":
				wantSuccess(t, res)
				doc, ok := res.ContentStream.(*document.Document)
				if !ok || len(doc.Services()) != 1 || doc.ID().String() != testutil.ExampleDID || doc.Services()[0].ID != "did:example:123#files" {
					t.Fatalf("selected document: %+v", res)
				}
			default:
				wantError(t, res, resolution.CodeRepresentationNotSupported)
			}
		})
	}
	t.Run("invalid accept makes no nested call", func(t *testing.T) {
		e := newEnv(t)
		wantError(t, e.deref(t, testutil.ExampleDID, resolution.DereferenceOptions{Accept: "text/uri-list;q=2"}), resolution.CodeInvalidOptions)
		if len(e.spy.calls) != 0 {
			t.Fatal("invalid options forwarded")
		}
	})
}
