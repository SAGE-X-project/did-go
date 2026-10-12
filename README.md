# did-go

A Go library for W3C Decentralized Identifiers. It implements DID Core 1.0 and
DID 1.1 over one superset core, the parts of Controlled Identifiers 1.0 that
DID 1.1 delegates to, and the DID Resolution v1.0 resolver, dereferencer and
HTTPS binding. Standard DID support is complete on its own; SAGE support is an
opt-in advanced extension in its own module, `advanced/sage`. The design is in
[`docs/`](docs/README.md).

## Packages

Shared types and contracts (no I/O, standard library only):
`spec`, `did`, `vm`, `document`, `representation`, `resolution`, `method`.

Players, one package per role. A player never imports another player:

| Role | Package |
|---|---|
| Producer and consumer | `producer`, `consumer` |
| DID resolver and DID URL dereferencer | `resolver`, `dereferencer` |
| DID methods | `method/key` (did:key), `method/web` (did:web) |
| DID controller | `controller` |
| Relying party (verification method retrieval) | `relyingparty` |
| DID Core 1.0 resolution functions | `resolution/compat` |
| DID Resolution HTTPS binding | `resolution/universal` |
| Resolution cache | `resolution/cache` |

`didkit` wires the standard players together; it never imports a driver, so a
did:key user does not pull in `net/http`.

`advanced/sage` (module `github.com/sage-x-project/did-go/advanced/sage`)
presents did:sage records as DID documents under the adopted rules of SAGE
0.10.0 chapter 10: the DID Core 1.0 and DID 1.1 projections, the exact accept
table of the SAGE interface, a did:sage driver, and a resolver and HTTP(S)
handler in front of the standard ones that add the DIDP-05 error mapping and
the `sageCode` problem member. Records come from a `Source` the deployment
configures; the module decides no trust and holds no key.

## Example

```go
r, err := didkit.NewResolver(key.New(producer.New()))
if err != nil {
	return err
}
d, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
if err != nil {
	return err
}
res := r.Resolve(ctx, d, resolution.ResolutionOptions{})
if e := res.ResolutionMetadata.Error; e != nil {
	return e
}
fmt.Println(res.Document.ID(), res.ResolutionMetadata.ContentType)
```

The runnable version is `ExampleNewResolver` in `didkit/example_test.go`.

## Conformance

`conformance/requirements.json` lists every normative statement of the pinned
specifications ([`docs/standards.md`](docs/standards.md)), and every in-scope
statement is named by a test. The independent
[did-inspector](https://github.com/SAGE-X-project/did-inspector) judges did-go
against the specification text with separate DID Core 1.0 and DID 1.1
profiles; its reports are in that repository's `docs/evidence`. Accepted
deviations are recorded as tensions in
[`docs/08-verification-report.md`](docs/08-verification-report.md).

## Not implemented yet

- Issuer, holder and verifier roles for verifiable credentials.
- A `Source` for eip155 registries. The SAGE Go core implements one for web
  registries (`pkg/agent/didsource010`); its eip155 observation does not yet
  carry the services, controller and observation metadata a projection needs.

Licensed under the Apache License, Version 2.0 (see `LICENSE`).
