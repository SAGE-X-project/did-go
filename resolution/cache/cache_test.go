package cache_test

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/testutil"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/spec"
)

var exampleDID = testutil.MustDID(testutil.ExampleDID)

// stack is a cache over a DefaultResolver over a fixture driver that labels
// ExampleDoc with a low-precision media type.
func stack(t *testing.T, opts ...cache.Option) (*cache.Resolver, *testutil.Driver) {
	t.Helper()
	drv := &testutil.Driver{Method: "example", Media: []string{spec.MediaTypeDID},
		Func: testutil.Static(testutil.ExampleDoc, "application/json", document.Metadata{VersionID: "1"})}
	reg, _ := method.NewRegistry(drv)
	inner, err := resolver.New(reg, consumer.New(), producer.New())
	if err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(inner, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, drv
}

// counter is an inner resolver that returns a fixed result and counts calls.
type counter struct {
	mu    sync.Mutex
	n     int
	res   resolution.Result
	calls []resolution.ResolutionOptions
}

func (c *counter) Resolve(_ context.Context, _ did.DID, opts resolution.ResolutionOptions) resolution.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.calls = append(c.calls, opts)
	return c.res
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestNew(t *testing.T) {
	if _, err := cache.New(nil); err == nil {
		t.Fatal("nil inner resolver")
	}
	if _, err := cache.New(&counter{}, nil, cache.WithMaxEntries(0), cache.WithTTL(0), cache.WithClock(nil)); err != nil {
		t.Fatal("ignored options")
	}
}

func TestCache(t *testing.T) {
	ctx := t.Context()
	t.Run("a successful result is cached per DID and options and returned as a copy", func(t *testing.T) {
		c, drv := stack(t)
		first := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{ExpandRelativeURLs: true})
		if first.ResolutionMetadata.Error != nil || first.Source == nil || first.Info.LowPrecision == nil {
			t.Fatalf("%v", first.ResolutionMetadata.Error)
		}
		first.Raw[0] = 'X'
		first.Source.Data[0] = 'X'
		first.Info.LowPrecision.Declared = "changed"
		first.DocumentMetadata.VersionID = "changed"
		second := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{ExpandRelativeURLs: true})
		if len(drv.Calls()) != 1 {
			t.Fatal("the second request is served from the cache")
		}
		if second.Raw[0] == 'X' || second.Source.Data[0] == 'X' || second.Info.LowPrecision.Declared != "application/json" ||
			second.DocumentMetadata.VersionID != "1" {
			t.Fatal("a caller changed the cached entry")
		}
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if len(drv.Calls()) != 2 || c.Len() != 2 {
			t.Fatal("other options are another entry")
		}
	})
	t.Run("failed resolutions are not cached", func(t *testing.T) {
		in := &counter{res: resolution.ErrorResult(resolution.NewError(resolution.CodeNotFound, ""))}
		c, _ := cache.New(in)
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if in.count() != 2 || c.Len() != 0 {
			t.Fatal("errors are not cached")
		}
	})
	t.Run("deactivated results are cached", func(t *testing.T) {
		in := &counter{res: resolution.Result{DocumentMetadata: document.Metadata{Deactivated: true}}}
		c, _ := cache.New(in)
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if res := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{}); !res.DocumentMetadata.Deactivated || in.count() != 1 {
			t.Fatal("deactivated")
		}
	})
	t.Run("resolution metadata is copied", func(t *testing.T) {
		in := &counter{res: resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did",
			Proof: []map[string]any{{"p": "1"}}, Extra: map[string]any{"x": map[string]any{"y": "z"}}}}}
		c, _ := cache.New(in)
		r1 := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		r1.ResolutionMetadata.Proof[0]["p"] = "changed"
		r1.ResolutionMetadata.Extra["x"].(map[string]any)["y"] = "changed"
		r2 := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if r2.ResolutionMetadata.Proof[0]["p"] != "1" || r2.ResolutionMetadata.Extra["x"].(map[string]any)["y"] != "z" {
			t.Fatal("resolution metadata shared")
		}
	})
	t.Run("entries expire after the TTL", func(t *testing.T) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		in := &counter{res: resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}}}
		c, _ := cache.New(in, cache.WithTTL(time.Minute), cache.WithClock(func() time.Time { return now }))
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		now = now.Add(59 * time.Second)
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		now = now.Add(time.Second)
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if in.count() != 2 {
			t.Fatalf("calls %d", in.count())
		}
	})
	t.Run("the least recently used entry is evicted", func(t *testing.T) {
		in := &counter{res: resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}}}
		c, _ := cache.New(in, cache.WithMaxEntries(2))
		a, b, x := resolution.ResolutionOptions{VersionID: "a"}, resolution.ResolutionOptions{VersionID: "b"}, resolution.ResolutionOptions{VersionID: "x"}
		c.Resolve(ctx, exampleDID, a)
		c.Resolve(ctx, exampleDID, b)
		c.Resolve(ctx, exampleDID, a) // a is now the most recently used
		c.Resolve(ctx, exampleDID, x) // evicts b
		if c.Len() != 2 || in.count() != 3 {
			t.Fatalf("len %d calls %d", c.Len(), in.count())
		}
		c.Resolve(ctx, exampleDID, a)
		c.Resolve(ctx, exampleDID, b)
		if in.count() != 4 {
			t.Fatalf("a stays cached and b was evicted: calls %d", in.count())
		}
	})
	t.Run("options that cannot be encoded bypass the cache", func(t *testing.T) {
		in := &counter{res: resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}}}
		c, _ := cache.New(in)
		o := resolution.ResolutionOptions{Extra: map[string]any{"n": math.Inf(1)}}
		c.Resolve(ctx, exampleDID, o)
		c.Resolve(ctx, exampleDID, o)
		if in.count() != 2 || c.Len() != 0 {
			t.Fatal("not cached")
		}
	})
	t.Run("concurrent use", func(t *testing.T) {
		in := &counter{res: resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}}}
		c, _ := cache.New(in, cache.WithMaxEntries(3))
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{VersionID: string(rune('a' + i%5))})
			})
		}
		wg.Wait()
		if c.Len() > 3 {
			t.Fatal("bounded")
		}
	})
}

func TestNoCache(t *testing.T) {
	ctx := t.Context()
	t.Run("noCache bypasses the cache, reaches the driver and refreshes the entry", func(t *testing.T) {
		c, drv := stack(t)
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		res := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{NoCache: true})
		calls := drv.Calls()
		if res.ResolutionMetadata.Error != nil || len(calls) != 2 || !calls[1].NoCache {
			t.Fatal("a fresh document is retrieved")
		}
		c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{})
		if len(drv.Calls()) != 2 || c.Len() != 1 {
			t.Fatal("the fresh result replaced the entry")
		}
	})
	t.Run("res10-crd20261001#caching.2 a resolver that denies resolution without caching answers FEATURE_NOT_SUPPORTED saying so", func(t *testing.T) {
		c, drv := stack(t, cache.RefuseNoCache())
		res := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{NoCache: true})
		e := res.ResolutionMetadata.Error
		if e == nil || e.Type != resolution.CodeFeatureNotSupported.TypeURL() || e.Detail != cache.NoCacheRefusedDetail ||
			res.Document != nil || !res.DocumentMetadata.IsEmpty() || len(drv.Calls()) != 0 {
			t.Fatalf("%v", e)
		}
		if res := c.Resolve(ctx, exampleDID, resolution.ResolutionOptions{}); res.ResolutionMetadata.Error != nil {
			t.Fatal("the client can resolve again without noCache")
		}
	})
}
