// Package didkit wires the did-go players into a ready DID resolver and DID
// URL dereferencer (docs/14 §6). It contains no resolution logic of its own:
// it builds the standard producer and consumer, a method.Registry of the
// drivers the caller passes, a resolver.DefaultResolver over them, an
// optional resolution/cache decorator, and a dereferencer over the result.
//
// didkit takes method.Method values from the caller and never imports a
// driver itself, so a program that resolves only did:key never links
// net/http:
//
//	p := producer.New()
//	r, err := didkit.NewResolver(key.New(p))                // did:key only
//	r, err = didkit.NewResolver(key.New(p), web.New(p, hc)) // adds did:web
//
// didkit does not include resolution/compat; a DID Core 1.0 caller wraps the
// resolver itself.
//
// NewResolver and NewDereferencer use the default configuration. A Kit
// built by New carries options for every assembled player and the producer
// those players share, which drivers can be built with as well.
package didkit

import (
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-go/resolver"
)

// config holds the options of every player a Kit assembles.
type config struct {
	producer     []producer.Option
	consumer     []consumer.Option
	resolver     []resolver.Option
	dereferencer []dereferencer.Option
	cache        []cache.Option
	cached       bool
}

// Option configures a Kit.
type Option func(*config)

// WithProducerOptions passes options to the standard producer
// (producer.New).
func WithProducerOptions(opts ...producer.Option) Option {
	return func(c *config) { c.producer = append(c.producer, opts...) }
}

// WithConsumerOptions passes options to the standard consumer
// (consumer.New) that reads every driver output.
func WithConsumerOptions(opts ...consumer.Option) Option {
	return func(c *config) { c.consumer = append(c.consumer, opts...) }
}

// WithResolverOptions passes options to the resolver (resolver.New).
func WithResolverOptions(opts ...resolver.Option) Option {
	return func(c *config) { c.resolver = append(c.resolver, opts...) }
}

// WithDereferencerOptions passes options to the dereferencer
// (dereferencer.New).
func WithDereferencerOptions(opts ...dereferencer.Option) Option {
	return func(c *config) { c.dereferencer = append(c.dereferencer, opts...) }
}

// WithCache puts a resolution/cache decorator in front of the resolver,
// configured with opts (cache.New). Without it the resolver keeps no cache.
func WithCache(opts ...cache.Option) Option {
	return func(c *config) {
		c.cached = true
		c.cache = append(c.cache, opts...)
	}
}

// Kit assembles players with one configuration. It is immutable and safe for
// concurrent use.
type Kit struct {
	cfg      config
	producer *producer.Producer
}

// New returns a Kit configured with opts. A nil option is ignored.
func New(opts ...Option) *Kit {
	var cfg config
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &Kit{cfg: cfg, producer: producer.New(cfg.producer...)}
}

// Producer returns the standard producer the Kit's players share. Drivers
// built with it (key.New(k.Producer())) write representations with the same
// options as the resolver.
func (k *Kit) Producer() *producer.Producer { return k.producer }

// NewResolver returns a resolver over the given drivers: a
// resolver.DefaultResolver with the Kit's producer, a consumer and a
// method.Registry of methods, wrapped in a cache when WithCache was given.
// A nil driver, a driver name that is not a method name, or a name given
// twice is an error (method.NewRegistry).
func (k *Kit) NewResolver(methods ...method.Method) (resolution.Resolver, error) {
	reg, err := method.NewRegistry(methods...)
	if err != nil {
		return nil, err
	}
	r, err := resolver.New(reg, consumer.New(k.cfg.consumer...), k.producer, k.cfg.resolver...)
	if err != nil {
		return nil, err
	}
	if !k.cfg.cached {
		return r, nil
	}
	c, err := cache.New(r, k.cfg.cache...)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// NewDereferencer returns a DID URL dereferencer over r with the Kit's
// producer. A nil resolver is an error.
func (k *Kit) NewDereferencer(r resolution.Resolver) (*dereferencer.Dereferencer, error) {
	return dereferencer.New(r, k.producer, k.cfg.dereferencer...)
}

// NewResolver returns a resolver over the given drivers with the default
// configuration; see Kit.NewResolver.
func NewResolver(methods ...method.Method) (resolution.Resolver, error) {
	return New().NewResolver(methods...)
}

// NewDereferencer returns a DID URL dereferencer over r with the default
// configuration; see Kit.NewDereferencer.
func NewDereferencer(r resolution.Resolver) (*dereferencer.Dereferencer, error) {
	return New().NewDereferencer(r)
}
