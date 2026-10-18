# Primary resource URLs

[DID Resolution 1.0 CRD, 1 October 2026, section 5.4.1](https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/#dereferencing-algorithm-resource) separates a present fragment before continuing with the primary resource URL. ResourceHandler now receives `u.WithoutFragment()`, including when the original fragment is explicitly empty. DID, path, raw query, query presence and percent-encoding remain unchanged. The original DIDURL value is not mutated.

The dispatcher retains the original URL for existing document/service fragment processing and for deferring content negotiation until that step. Removing its fragment early would lose that state. Resolver input and option forwarding, handler order, declined results, diagnostics and handled results retain their existing contracts.

Callbacks previously documented as receiving the full URL must migrate if they use Fragment or HasFragment for routing. They now receive only the primary URL. Returning handled=true still returns that callback's result as final, including errors or empty content; this change does not add centralized fragment processing for arbitrary callback documents, lists or media. Do not infer complete extension/media-fragment conformance from this narrow repair.

Unit scenarios compare literal absent/empty/nonempty fragments, encoded delimiters, raw query presence, ordered handlers, final/declined/error results, invalid input and unchanged document/service behavior. Owned loopback TLS tests carry the complete logical DID URL through GET and POST clients and direct GET wire checks, recording both the complete dereference input and the fragment-free handler argument. No external registry, deployment, transaction or attack reproduction is involved.
