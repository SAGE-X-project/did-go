# Forwarding dereferencing options

This behavior follows DID Resolution v1.0 CRD 2026-10-01,
[section 5.4.1](https://www.w3.org/TR/2026/CRD-did-resolution-20261001/#dereferencing-algorithm-resource):
all dereferencing options and DID parameters reach the nested resolution
algorithm. In particular, `accept` is forwarded unchanged even for
`text/uri-list`. The former filtering exception has been removed.

## Separate intermediate and direct resolution

The direct resolver remains strict: an unsupported representation preference
returns `FEATURE_NOT_SUPPORTED` with no document. The dereferencer never
silently retries that failure with a different preference.

Construct a distinct resolver for intermediate document retrieval:

```go
direct, err := resolver.New(registry, consumer, producer)
// Check err. Keep direct for direct and HTTP resolution.
intermediate, err := resolver.New(registry, consumer, producer,
    resolver.ForDereferencing())
// Check err. Use intermediate only for this role.
deref, err := dereferencer.New(intermediate, producer)
// Check err. A binding can use direct together with deref.
```

`ForDereferencing()` is a local constructor policy, never a request option or
an inference from service parameters, ambient context or the caller stack.
The resolver receives and validates the original options. Only when a valid
preference matches no supported DID representation does its intermediate
representation selection use the driver's actual conforming DID representation.
It does not claim that a DID document has media type `text/uri-list`.
Section 4.1 defines `accept` as a preference and conditions its SHOULD on a
representation being supported and available. This explicit intermediate
policy is an implementation interpretation of that condition.

Malformed options, unknown extensions, driver errors, invalid metadata or
DID documents, mismatched IDs and producer failures remain errors. Negotiable
DID preferences retain ordinary negotiation and transcoding. No fallback is
attempted after a real producer failure. Final content selection still uses
the original dereferencing preference and rejects unsupported content.

Keep direct and intermediate resolver instances and caches separate. Do not
expose the intermediate instance as a strict direct or HTTP resolution endpoint.
A remote resolver or proxy that rejects the original preference is not silently
reconfigured; choose an explicitly compatible document retrieval implementation.

## Migration and verification scope

Callers constructing a dereferencer over the default strict resolver need a
separate intermediate instance for URI-list service selection. With didkit,
construct that instance using a separate Kit with
`didkit.WithResolverOptions(resolver.ForDereferencing())`. Passing a resolver
to `NewDereferencer` does not change its policy.

Safe tests compare unchanged nested options, selected documents and literal
service URL lists. They also preserve strict refusal, invalid-input and actual
failure behavior, including independent caches and concurrent calls. No service
endpoint is contacted. These observations do not establish operational registry
authority or complete HTTP, URI and DID conformance. External SAGE and Rust
consumer adoption is a separate integration task.
