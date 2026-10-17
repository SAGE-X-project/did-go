package universal_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
)

func TestRecursiveFragmentTLS(t *testing.T) {
	for _, number := range []string{"2", "18446744073709551615", "0.12345678901234567890123456789"} {
		t.Run(number, func(t *testing.T) {
			expected := `{"id":"did:example:resources#target","number":` + number + `}`
			input := `{"id":"did:example:resources","service":[{"id":"#one","type":"Messaging","serviceEndpoint":{"nested":[` + expected + `]}}]}`
			drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID}, Func: testutil.Static(input, spec.MediaTypeDID, document.Metadata{})}
			reg, err := method.NewRegistry(drv)
			if err != nil {
				t.Fatal(err)
			}
			p := producer.New()
			r, err := resolver.New(reg, consumer.New(), p, resolver.ForDereferencing())
			if err != nil {
				t.Fatal(err)
			}
			d, err := dereferencer.New(r, p)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewTLSServer(universal.NewHandler(r, d, universal.WithProducer(p)))
			t.Cleanup(srv.Close)
			client, err := universal.NewClient(srv.URL+universal.DefaultPathPrefix, srv.Client(), consumer.New())
			if err != nil {
				t.Fatal(err)
			}
			u, err := did.ParseURL("did:example:resources#target")
			if err != nil {
				t.Fatal(err)
			}
			got := client.Dereference(t.Context(), u, resolution.DereferenceOptions{Accept: spec.MediaTypeDID})
			if got.DereferencingMetadata.Error != nil || got.DereferencingMetadata.ContentType != "application/ld+json" {
				t.Fatalf("owned TLS dereference failed: %+v", got)
			}
			// The low-precision client returns bytes if a valid JSON number cannot fit
			// its INFRA value model. Inspect the actual wire bytes without narrowing it.
			resp, body := request(t, srv, "did:example:resources%23target", spec.MediaTypeDID)
			if resp.StatusCode != 200 {
				t.Fatalf("TLS status %d: %s", resp.StatusCode, body)
			}
			decode := func(b []byte) any {
				var v any
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				if err := dec.Decode(&v); err != nil {
					t.Fatal(err)
				}
				return v
			}
			if !reflect.DeepEqual(decode([]byte(body)), decode([]byte(expected))) {
				t.Fatalf("TLS changed selected map: %s", body)
			}
			missing, _ := did.ParseURL("did:example:resources#absent")
			if result := client.Dereference(t.Context(), missing, resolution.DereferenceOptions{Accept: spec.MediaTypeDID}); result.ContentStream != nil || result.DereferencingMetadata.Error == nil {
				t.Fatal("missing fragment became content")
			}
		})
	}
}
