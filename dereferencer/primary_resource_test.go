package dereferencer_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

func TestPrimaryResourceURLs(t *testing.T) {
	for _, tc := range []struct{ name, tail, primary string }{
		{"absent", "/resource", "/resource"},
		{"fragment", "/resource#part", "/resource"},
		{"empty fragment", "/resource#", "/resource"},
		{"question in fragment", "/resource#part?piece", "/resource"},
		{"encoded path", "/res%23x#part%2Fone", "/res%23x"},
		{"encoded query", "/resource?relativeRef=next%23part#tail", "/resource?relativeRef=next%23part"},
		{"empty query", "/resource?#part", "/resource?"},
		{"empty query and fragment", "/resource?#", "/resource?"},
		{"query only", "?relativeRef=next#part", "?relativeRef=next"},
		{"query delimiters", "/resource?relativeRef=a%3Fb%23c#part%23two", "/resource?relativeRef=a%3Fb%23c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := resolution.DereferenceOptions{Accept: spec.MediaTypeDID, Extra: map[string]any{"trace": "unit"}}
			before := resolution.DereferenceOptions{Accept: spec.MediaTypeDID, Extra: map[string]any{"trace": "unit"}}
			input := testutil.MustURL(testutil.ExampleDID + tc.tail)
			original := input
			expected := testutil.MustURL(testutil.ExampleDID + tc.primary)
			var urls []did.DIDURL
			var calls []resolution.DereferenceOptions
			var docs []resolution.Result
			capture := func(_ context.Context, u did.DIDURL, res resolution.Result, o resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				urls = append(urls, u)
				calls = append(calls, o)
				docs = append(docs, res)
				return resolution.DereferenceResult{ContentStream: []byte("ignored")}, false
			}
			final := func(ctx context.Context, u did.DIDURL, res resolution.Result, o resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				_, _ = capture(ctx, u, res, o)
				return resolution.DereferenceResult{ContentStream: []byte("primary"), DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"}}, true
			}
			drv := fixture(testutil.ExampleDoc, spec.MediaTypeDID, document.Metadata{VersionID: "1"})
			spy := &spy{inner: newResolver(t, []resolver.Option{resolver.AcceptOptions("trace")}, drv)}
			d, err := dereferencer.New(spy, producer.New(), dereferencer.WithResourceHandler(capture), dereferencer.WithResourceHandler(final))
			if err != nil {
				t.Fatal(err)
			}
			got := d.Dereference(t.Context(), input, opts)
			wantSuccess(t, got)
			if string(got.ContentStream.([]byte)) != "primary" || !reflect.DeepEqual(urls, []did.DIDURL{expected, expected}) {
				t.Fatalf("primary URLs or final result changed: %v %+v", urls, got)
			}
			for i, u := range urls {
				if u.HasFragment() || u.Fragment() != "" || u.Path() != expected.Path() || u.Query() != expected.Query() || u.HasQuery() != expected.HasQuery() || !reflect.DeepEqual(calls[i], before) || docs[i].Document.ID().String() != testutil.ExampleDID || docs[i].DocumentMetadata.VersionID != "1" {
					t.Fatal("same-call URL/document/options binding changed")
				}
			}
			if input != original || !reflect.DeepEqual(opts, before) || len(spy.calls) != 1 {
				t.Fatal("original input/options or resolver call count changed")
			}
		})
	}
}

func TestPrimaryResourceHandlerResults(t *testing.T) {
	for _, mode := range []string{"content", "error", "nil", "decline", "document", "urls"} {
		t.Run(mode, func(t *testing.T) {
			first, second := 0, 0
			expected := resolution.DereferenceResult{ContentStream: []byte("final"), DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"}}
			if mode == "error" {
				expected = resolution.ErrorDereferenceResult(resolution.NewError(resolution.CodeNotFound, "unit"))
			}
			if mode == "nil" {
				expected = resolution.DereferenceResult{}
			}
			one := func(_ context.Context, u did.DIDURL, res resolution.Result, _ resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				first++
				if mode == "document" {
					expected = resolution.DereferenceResult{ContentStream: res.Document, DereferencingMetadata: resolution.DereferencingMetadata{ContentType: spec.MediaTypeDID}}
				}
				if mode == "urls" {
					expected = resolution.DereferenceResult{ContentStream: []string{"https://example.invalid/primary"}, DereferencingMetadata: resolution.DereferencingMetadata{ContentType: dereferencer.MediaTypeURIList}}
				}
				if u.HasFragment() || u.String() != testutil.ExampleDID+"/resource" {
					t.Fatal("unadjusted first handler")
				}
				return expected, mode != "decline"
			}
			two := func(_ context.Context, u did.DIDURL, _ resolution.Result, _ resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				second++
				if u.HasFragment() {
					t.Fatal("unadjusted next handler")
				}
				return resolution.DereferenceResult{}, false
			}
			got := newEnv(t, dereferencer.WithResourceHandler(one), dereferencer.WithResourceHandler(two)).deref(t, testutil.ExampleDID+"/resource#part", resolution.DereferenceOptions{})
			if first != 1 {
				t.Fatal(first)
			}
			if mode == "decline" {
				wantError(t, got, resolution.CodeNotFound)
				if second != 1 {
					t.Fatal(second)
				}
			} else if second != 0 || !reflect.DeepEqual(got, expected) {
				t.Fatal("handled final result changed")
			}
		})
	}
}

func TestPrimaryResourceRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		opts        resolution.DereferenceOptions
		code        resolution.Code
	}{
		{"malformed", testutil.ExampleDID + "/resource#bad%", resolution.DereferenceOptions{}, resolution.CodeInvalidDIDURL},
		{"relative", "#part", resolution.DereferenceOptions{}, resolution.CodeInvalidDIDURL},
		{"options", testutil.ExampleDID + "/resource#part", resolution.DereferenceOptions{Extra: map[string]any{"accept": "application/did"}}, resolution.CodeInvalidOptions},
		{"unknown method", "did:other:123/resource#part", resolution.DereferenceOptions{}, resolution.CodeMethodNotSupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := func(context.Context, did.DIDURL, resolution.Result, resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				calls++
				return resolution.DereferenceResult{}, false
			}
			got := newEnv(t, dereferencer.WithResourceHandler(h)).deref(t, tc.input, tc.opts)
			wantError(t, got, tc.code)
			if calls != 0 {
				t.Fatal("refused input reached a handler")
			}
		})
	}
}

func TestPrimaryResourceFragmentFlow(t *testing.T) {
	for _, mode := range []string{"method", "missing", "service", "endpoint conflict"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			h := func(context.Context, did.DIDURL, resolution.Result, resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
				calls++
				return resolution.DereferenceResult{}, false
			}
			e := newEnv(t, dereferencer.WithResourceHandler(h))
			switch mode {
			case "method":
				got := e.deref(t, testutil.ExampleDID+"#key-2", resolution.DereferenceOptions{Accept: "image/png"})
				wantSuccess(t, got)
				if got.ContentStream.(vm.Method).ID.String() != testutil.ExampleDID+"#key-2" {
					t.Fatal("lost original document fragment")
				}
			case "missing":
				wantError(t, e.deref(t, testutil.ExampleDID+"#absent", resolution.DereferenceOptions{}), resolution.CodeNotFound)
			case "service":
				got := e.deref(t, testutil.ExampleDID+"?service=messages#part", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList})
				wantSuccess(t, got)
				if !reflect.DeepEqual(got.ContentStream, []string{"https://example.com/messages/8377464#part"}) {
					t.Fatal("lost service fragment")
				}
			case "endpoint conflict":
				wantError(t, e.deref(t, testutil.ExampleDID+"?service=files#part", resolution.DereferenceOptions{Accept: dereferencer.MediaTypeURIList}), resolution.CodeInvalidDIDURL)
			}
			if calls != 0 {
				t.Fatal("document/service path reached extension handler")
			}
		})
	}
}
