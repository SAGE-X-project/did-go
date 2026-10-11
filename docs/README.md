# did-go design

These documents design a Go implementation that meets the normative
requirements of W3C Decentralized Identifiers v1.1 (Candidate Recommendation)
and v1.0 (Recommendation, 2022-07-19), supporting both versions. Standard DID
support is complete on its own; SAGE support is an opt-in advanced extension
([12](12-standard-core-and-sage-extension.md)).

The design is a translation of the canonical design notes kept by the
maintainers, updated on 2026-10-11. Nothing here is implemented yet, and
nothing here is a conformance claim.

## Key points from the specification review

The design follows v1.1, and three delegation boundaries shape it. The
normative content of the two delegated specifications, Controlled Identifiers
and DID Resolution, is extracted into [06](06-cid-data-model.md) and
[07](07-did-resolution-contract.md).

1. **DID Core does not contain the resolution and dereferencing algorithms.**
   They are delegated to DID Resolution v1.0 (Candidate Recommendation Draft,
   2026-10-01). Errors are RFC 9457 problem details whose `type` is a
   `…#CODE` URL. There is no `resolveRepresentation()`. `deactivated` is not an
   error (HTTP 410). See [07](07-did-resolution-contract.md).
2. **The verification method, service and relationship data model is
   delegated to Controlled Identifiers 1.0.** A verification method has at
   most one public key material property and at most one secret key material
   property (the type decides which, and a method without public key material
   cannot verify proofs), Multikey uses multicodec prefixes, private JWK members are
   forbidden, and verification method retrieval binds both ways. DID adds only
   its own constraints (`id` is a DID URL, `controller` is a DID). See
   [06](06-cid-data-model.md).
3. **One media type.** A v1.1 DID document has the single media type
   `application/did`. JSON and JSON-LD are the same representation,
   distinguished only by the presence of `@context`. Resolver results use
   `application/did-resolution` and `application/did-url-dereferencing`.
4. **v1.0 is supported at the same time.** The v1.1 data model is a superset of
   v1.0 with identical syntax. The versions differ in three places only: the
   serialization envelope (`@context` `…/did/v1` or `…/did/v1.1`, media types
   `did+json` and `did+ld+json` or `application/did`), the resolution contract
   (`resolveRepresentation` and string errors or RFC 9457), and DID parameters
   (`hl` or `serviceType`). The strategy is **one superset core plus version
   adapters**. See [09](09-v1.0-compat.md).

## Documents

| Document | Contents |
|---|---|
| [00-feature-definition.md](00-feature-definition.md) | Functional and non-functional requirements, normative basis, acceptance criteria, scope and traceability |
| [01-use-cases.md](01-use-cases.md) | Actors, use case diagram, twelve detailed use cases, use case to requirement matrix |
| [02-sequence-diagrams.md](02-sequence-diagrams.md) | Sequences for parsing, building, producing, consuming, resolving, dereferencing, CRUD, verification method selection and the v1.0 adapter |
| [03-component-diagram.md](03-component-diagram.md) | Package structure, responsibilities, ports and adapters, deployment view |
| [04-state-diagrams.md](04-state-diagrams.md) | DID lifecycle and the state machines for parsing, representation, resolution and verification method references |
| [05-go-design.md](05-go-design.md) | Package layout, types and interfaces, error design, traceability, tests, design decisions |
| [06-cid-data-model.md](06-cid-data-model.md) | Controlled Identifiers 1.0 rules for verification methods, services and relationships, Multikey and JWK, retrieval and fragment algorithms, Go mapping |
| [07-did-resolution-contract.md](07-did-resolution-contract.md) | Resolve and dereference, options, RFC 9457 errors, DID parameters, HTTP binding, Go mapping |
| [08-verification-report.md](08-verification-report.md) | Record of the audits against the three specifications and the tensions found between them |
| [09-v1.0-compat.md](09-v1.0-compat.md) | v1.0 Recommendation comparison, version detection and production profiles, the v1.0 resolution adapter and its error mapping |
| [10-abnf-appendix.md](10-abnf-appendix.md) | Full ABNF (the parser's reference), conformance test vectors, context file digests |
| [12-standard-core-and-sage-extension.md](12-standard-core-and-sage-extension.md) | Standard-first principle and the advanced SAGE extension, module layout, trust boundary, agent information management, role layers, decisions 16 to 23 |
| [13-xbar-verification.md](13-xbar-verification.md) | X-bar verification of both language versions against the pinned specifications: method, results by round, changes, recorded deviations and remaining risk |
| [14-implementation-architecture.md](14-implementation-architecture.md) | Implementation architecture: layers, shared types and contracts, separated players, wiring, spec-driven development, per-version inspection, pinned method specifications, order of implementation |
| [standards.md](standards.md) | Dated W3C publications the design follows, with SHA-256 |

Number 11 is not published here: it is a jurisdiction-specific legal review
maintained outside this repository.

## Reading order

00 (what), 01 (who and when), 02 and 04 (how it flows), 03 (where), 05 (how in
Go), 06 and 07 (the delegated specifications in detail), 09 (v1.0
compatibility), 10 (starting implementation: ABNF, test vectors, assets), 12
(the standard core, the SAGE extension and the repository layout). 08 holds the
verification history, and 13 the X-bar verification against the
specifications. 14 is the implementation architecture.

## Provenance

Line-number citations refer to the pinned sources below. The dated W3C
publications and their SHA-256 values are in [standards.md](standards.md).

| Specification | Status | Source | Pinned revision |
|---|---|---|---|
| DID Core v1.1 | Candidate Recommendation Snapshot | [w3c/did](https://github.com/w3c/did) `index.html`, [W3C TR](https://www.w3.org/TR/2026/CR-did-1.1-20260305/) | `13626ba6aac9` (2026-03-05) |
| DID Core v1.0 | Recommendation (2022-07-19) | [W3C TR](https://www.w3.org/TR/2022/REC-did-core-20220719/) | Published fixed document; cited by section |
| Controlled Identifiers 1.0 | Recommendation (2025-05-15) | [w3c/cid](https://github.com/w3c/cid) `index.html`, [W3C TR](https://www.w3.org/TR/2025/REC-cid-1.0-20250515/) | `2b962ac29e13` (2026-07-13) |
| DID Resolution v1.0 | Candidate Recommendation Draft | [W3C TR](https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/) | Dated publication 2026-10-01; cited by section id |
