package universal_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestNestedExpansionTLS(t *testing.T) {
	for _, number := range []string{"2", "18446744073709551615", "0.12345678901234567890123456789"} {
		t.Run(number, func(t *testing.T) {
			input := `{"id":"did:example:resources","service":[{"id":"#one","type":"Messaging","serviceEndpoint":{"id":"#target","number":` + number + `,"label":"#unchanged"}}]}`
			drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID}, Func: testutil.Static(input, spec.MediaTypeDID, document.Metadata{})}
			reg, e := method.NewRegistry(drv)
			if e != nil {
				t.Fatal(e)
			}
			p := producer.New()
			r, e := resolver.New(reg, consumer.New(), p)
			if e != nil {
				t.Fatal(e)
			}
			d, e := dereferencer.New(r, p)
			if e != nil {
				t.Fatal(e)
			}
			srv := httptest.NewTLSServer(universal.NewHandler(r, d, universal.WithProducer(p)))
			t.Cleanup(srv.Close)
			c, e := universal.NewClient(srv.URL+universal.DefaultPathPrefix, srv.Client(), consumer.New())
			if e != nil {
				t.Fatal(e)
			}
			id, _ := did.Parse("did:example:resources")
			decode := func(b []byte) map[string]any {
				v := map[string]any{}
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				if err := dec.Decode(&v); err != nil {
					t.Fatal(err)
				}
				return v
			}
			for _, enabled := range []bool{false, true} {
				got := c.Resolve(t.Context(), id, resolution.ResolutionOptions{Accept: spec.MediaTypeDID, ExpandRelativeURLs: enabled})
				if got.ResolutionMetadata.Error != nil || got.Document == nil {
					t.Fatal("owned TLS resolve failed", got.ResolutionMetadata.Error)
				}
				child := "#target"
				service := "#one"
				if enabled {
					child = "did:example:resources" + child
					service = "did:example:resources" + service
				}
				ep := got.Document.Services()[0].ServiceEndpoint[0].Map
				if ep["id"] != child || fmt.Sprint(ep["number"]) != number || ep["label"] != "#unchanged" {
					t.Fatal("TLS client changed endpoint", ep)
				}
				response, body := request(t, srv, fmt.Sprintf("did%%3Aexample%%3Aresources?expandRelativeUrls=%t", enabled), spec.MediaTypeDID)
				if response.StatusCode != 200 {
					t.Fatal(response.StatusCode, body)
				}
				actual := decode([]byte(body))
				delete(actual, "@context")
				expected := decode([]byte(`{"id":"did:example:resources","service":[{"id":"` + service + `","type":"Messaging","serviceEndpoint":{"id":"` + child + `","number":` + number + `,"label":"#unchanged"}}]}`))
				if !reflect.DeepEqual(actual, expected) {
					t.Fatal("TLS wire changed unrelated values", body)
				}
			}
		})
	}
}
