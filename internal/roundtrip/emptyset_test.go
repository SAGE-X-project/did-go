package roundtrip

import (
	"bytes"
	"testing"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// An empty verificationMethod or service set is a conforming value
// (core10#verification-methods.2, cid10#verification-methods.2: "a set of
// verification methods"; core10#services.2, cid10#services.2: "a set of
// services"), so it survives consumption and production, and an absent
// property stays absent (cid10#verification-methods.1: OPTIONAL).
func TestEmptySetsRoundTrip(t *testing.T) {
	cases := []struct {
		mediaType string
		in        string
		opts      representation.ProduceOptions
	}{
		{spec.MediaTypeDIDJSON, `{"id":"did:example:a","verificationMethod":[],"service":[]}`,
			representation.ProduceOptions{Version: spec.V10}},
		{spec.MediaTypeDID, `{"id":"did:example:a","verificationMethod":[],"service":[]}`,
			representation.ProduceOptions{Version: spec.V11}},
		{spec.MediaTypeDIDJSON, `{"id":"did:example:a"}`, representation.ProduceOptions{Version: spec.V10}},
	}
	for _, c := range cases {
		d, _, err := consumer.New().Consume([]byte(c.in), c.mediaType, representation.ConsumeOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		out, _, err := producer.New().Produce(d, c.opts)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if !bytes.Equal(out, []byte(c.in)) {
			t.Errorf("round trip of %s gave %s", c.in, out)
		}
	}
}

func TestBuilderEmptySetIsPresent(t *testing.T) {
	id, _ := did.Parse("did:example:a")
	d, err := document.NewBuilder(id).VerificationMethod().Service().Build()
	if err != nil {
		t.Fatal(err)
	}
	if d.VerificationMethods() == nil || len(d.VerificationMethods()) != 0 || d.Services() == nil || len(d.Services()) != 0 {
		t.Errorf("empty sets are not present: %v %v", d.VerificationMethods(), d.Services())
	}
	again, err := document.NewBuilderFrom(d).Build()
	if err != nil || again.VerificationMethods() == nil || again.Services() == nil {
		t.Errorf("NewBuilderFrom dropped an empty set: %v", err)
	}
	absent, _ := document.NewBuilder(id).Build()
	if absent.VerificationMethods() != nil || absent.Services() != nil {
		t.Error("absent sets became present")
	}
}
