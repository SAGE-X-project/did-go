// Package cache is a caching decorator for any resolution.Resolver (DID
// Resolution v1.0 CRD 2026-10-01 §13.2, docs/14 §5).
//
// "A DID resolver may maintain a generic cache of DID documents." Resolver
// keeps successful results, deactivated ones included, in a bounded
// in-memory cache with least-recently-used eviction and a time to live.
// Failed resolutions are never cached, because a DID that was not found may
// be created later. Entries are keyed by the DID and every resolution option
// except noCache, so results for different representations, versions or
// expansion never mix. Results are deep copies in both directions, so a
// caller can never change a cached entry.
//
// The noCache option (§13.2: "true": "Request that caching is disabled and a
// fresh DID document is retrieved from the verifiable data registry") is
// honoured by default: the cache is bypassed, the inner resolver is called
// with noCache so that caches below are bypassed too, and the fresh result
// replaces the cached one. A resolver that wants to protect the registry can
// refuse instead (RefuseNoCache); it then answers FEATURE_NOT_SUPPORTED with
// a detail that says bypassing the cache is not permitted ("Resolvers that
// deny resolution without caching MUST respond with a FEATURE_NOT_SUPPORTED
// error that makes it clear that bypassing the cache was not permitted so the
// client can attempt to resolve without using noCache").
package cache

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/vm"
)

// Defaults of a Resolver; see WithMaxEntries and WithTTL.
const (
	DefaultMaxEntries = 1024
	DefaultTTL        = 5 * time.Minute
)

// NoCacheRefusedDetail is the FEATURE_NOT_SUPPORTED detail of a refused
// noCache request.
const NoCacheRefusedDetail = "bypassing the cache (noCache) is not permitted by this resolver; resolve again without noCache"

// Resolver is a resolution.Resolver that caches the results of another. It
// is safe for concurrent use when the inner resolver is.
type Resolver struct {
	inner   resolution.Resolver
	max     int
	ttl     time.Duration
	refuse  bool
	now     func() time.Time
	mu      sync.Mutex
	order   *list.List // front is most recently used; values are *entry
	entries map[string]*list.Element
}

type entry struct {
	key     string
	expires time.Time
	result  resolution.Result
}

var _ resolution.Resolver = (*Resolver)(nil)

// Option configures a Resolver.
type Option func(*Resolver)

// WithMaxEntries bounds the number of cached results; the least recently
// used is evicted first. A value of zero or less keeps DefaultMaxEntries.
func WithMaxEntries(n int) Option {
	return func(r *Resolver) {
		if n > 0 {
			r.max = n
		}
	}
}

// WithTTL sets how long a result stays cached. A value of zero or less keeps
// DefaultTTL.
func WithTTL(d time.Duration) Option {
	return func(r *Resolver) {
		if d > 0 {
			r.ttl = d
		}
	}
}

// RefuseNoCache makes the resolver deny requests with noCache instead of
// bypassing the cache.
func RefuseNoCache() Option {
	return func(r *Resolver) { r.refuse = true }
}

// WithClock sets the clock used for expiry, for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Resolver) {
		if now != nil {
			r.now = now
		}
	}
}

// New returns a caching resolver in front of inner. A nil inner resolver is
// an error.
func New(inner resolution.Resolver, opts ...Option) (*Resolver, error) {
	if inner == nil {
		return nil, errors.New("cache: an inner resolver is required")
	}
	r := &Resolver{inner: inner, max: DefaultMaxEntries, ttl: DefaultTTL, now: time.Now,
		order: list.New(), entries: map[string]*list.Element{}}
	for _, o := range opts {
		if o != nil {
			o(r)
		}
	}
	return r, nil
}

// Resolve returns a cached result for d and opts when one is fresh, and
// otherwise resolves with the inner resolver and caches a successful result.
func (r *Resolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	if opts.NoCache && r.refuse {
		return resolution.ErrorResult(resolution.NewError(resolution.CodeFeatureNotSupported, NoCacheRefusedDetail))
	}
	k, ok := cacheKey(d, opts)
	if !ok {
		return r.inner.Resolve(ctx, d, opts)
	}
	if !opts.NoCache {
		if res, hit := r.get(k); hit {
			return res
		}
	}
	res := r.inner.Resolve(ctx, d, opts)
	if res.ResolutionMetadata.Error == nil {
		r.put(k, res)
	}
	return res
}

// Len returns the number of cached results, expired ones included until they
// are looked up or evicted.
func (r *Resolver) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.order.Len()
}

// cacheKey identifies a request: the DID and the JSON encoding of the
// options without noCache (encoding/json sorts map keys, so the encoding is
// deterministic). Options that cannot be encoded are not cached.
func cacheKey(d did.DID, opts resolution.ResolutionOptions) (string, bool) {
	opts.NoCache = false
	b, err := json.Marshal(opts)
	if err != nil {
		return "", false
	}
	return d.String() + " " + string(b), true
}

func (r *Resolver) get(k string) (resolution.Result, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.entries[k]
	if !ok {
		return resolution.Result{}, false
	}
	e := el.Value.(*entry)
	if !r.now().Before(e.expires) {
		r.order.Remove(el)
		delete(r.entries, k)
		return resolution.Result{}, false
	}
	r.order.MoveToFront(el)
	return clone(e.result), true
}

func (r *Resolver) put(k string, res resolution.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := &entry{key: k, expires: r.now().Add(r.ttl), result: clone(res)}
	if el, ok := r.entries[k]; ok {
		el.Value = e
		r.order.MoveToFront(el)
		return
	}
	r.entries[k] = r.order.PushFront(e)
	for r.order.Len() > r.max {
		last := r.order.Back()
		r.order.Remove(last)
		delete(r.entries, last.Value.(*entry).key)
	}
}

// clone returns a deep copy of a successful result. The document is
// immutable and shared.
func clone(res resolution.Result) resolution.Result {
	c := res
	c.Raw = slices.Clone(res.Raw)
	if res.Source != nil {
		c.Source = &resolution.SourceBytes{Data: slices.Clone(res.Source.Data), ContentType: res.Source.ContentType}
	}
	if res.Info.LowPrecision != nil {
		lp := *res.Info.LowPrecision
		c.Info.LowPrecision = &lp
	}
	c.Info.DroppedTerms = slices.Clone(res.Info.DroppedTerms)
	c.ResolutionMetadata = cloneMetadata(res.ResolutionMetadata)
	c.DocumentMetadata = res.DocumentMetadata.Clone()
	return c
}

func cloneMetadata(m resolution.ResolutionMetadata) resolution.ResolutionMetadata {
	c := m // only successful results, without Error, are cached
	if m.Proof != nil {
		c.Proof = make([]map[string]any, len(m.Proof))
		for i, p := range m.Proof {
			c.Proof[i] = vm.CloneJSONMap(p)
		}
	}
	c.Extra = vm.CloneJSONMap(m.Extra)
	return c
}
