package didkit_test

import (
	"context"
	"fmt"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/didkit"
	"github.com/sage-x-project/did-go/method/key"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-go/vm"
)

const exampleKeyDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

// A did:key DID resolves end to end: didkit wires the resolver, the caller
// supplies the driver.
func ExampleNewResolver() {
	p := producer.New()
	r, err := didkit.NewResolver(key.New(p))
	if err != nil {
		fmt.Println(err)
		return
	}
	d, err := did.Parse(exampleKeyDID)
	if err != nil {
		fmt.Println(err)
		return
	}
	res := r.Resolve(context.Background(), d, resolution.ResolutionOptions{})
	if e := res.ResolutionMetadata.Error; e != nil {
		fmt.Println(e.Detail)
		return
	}
	fmt.Println(res.Document.ID())
	fmt.Println(res.ResolutionMetadata.ContentType)
	fmt.Println(len(res.Document.VerificationMethods()))
	// Output:
	// did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
	// application/did
	// 1
}

// A DID URL with a fragment dereferences to the verification method it
// names.
func ExampleNewDereferencer() {
	r, err := didkit.NewResolver(key.New(producer.New()))
	if err != nil {
		fmt.Println(err)
		return
	}
	deref, err := didkit.NewDereferencer(r)
	if err != nil {
		fmt.Println(err)
		return
	}
	u := exampleKeyDID + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	res := deref.DereferenceString(context.Background(), u, resolution.DereferenceOptions{})
	if e := res.DereferencingMetadata.Error; e != nil {
		fmt.Println(e.Detail)
		return
	}
	m, ok := res.ContentStream.(vm.Method)
	if !ok {
		fmt.Printf("%T\n", res.ContentStream)
		return
	}
	fmt.Println(m.Type)
	// Output:
	// Multikey
}

// A Kit shares one configuration across the players it assembles; here the
// resolver is cached and the driver uses the Kit's producer.
func ExampleKit() {
	kit := didkit.New(didkit.WithCache(cache.WithTTL(time.Minute)))
	r, err := kit.NewResolver(key.New(kit.Producer()))
	if err != nil {
		fmt.Println(err)
		return
	}
	d, err := did.Parse(exampleKeyDID)
	if err != nil {
		fmt.Println(err)
		return
	}
	res := r.Resolve(context.Background(), d, resolution.ResolutionOptions{Accept: "application/did+ld+json"})
	fmt.Println(res.ResolutionMetadata.ContentType)
	_, cached := r.(*cache.Resolver)
	fmt.Println(cached)
	// Output:
	// application/did+ld+json
	// true
}
