# Observing both SAGE DID views

`advanced/sage.ObserveViews` implements the existing single-observation rule in
[SAGE 0.10.0 chapter 10 DIDP-03](https://github.com/SAGE-X-project/sage-spec/blob/06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b/spec/10-resolution.md#8-projection-equivalence--didp-03-r-4-r-14).
It is an additive library operation, not a new protocol version or HTTP format.
The two projections and the standard resolver interface remain as documented in
[the standard core and SAGE extension](12-standard-core-and-sage-extension.md).

Pass an explicitly configured `sage.Source`, a canonical DID, a context and a
conforming `representation.Producer` to `sage.ObserveViews`. The source remains
responsible for authoritative proofs, freshness, full record validation and
history. A peer's document, alias or resolver URL never selects that source.
The operation reads once, validates the identifier and record, snapshots mutable
members and produces Core 1.0 then DID 1.1 from that same observation. Every new
invocation observes again. The returned `*sage.Views` exposes `Core10` and
`DID11`, each with independently owned `Data`, `ContentType` and `Metadata`.

Do not call two independent single-view resolutions when a coherent pair is
required. Equal version strings in two independently fetched responses do not
establish that they came from one observation. Conversely, this operation does
not make separate HTTP requests transactional or reconfigure an existing driver.

A producer can reuse its scratch buffer: the first output is copied before the
second production call. Neither returned output nor its metadata aliases the
other view or a later call. The source must return stable record values during
the operation; copying does not synchronize a source that mutates them
concurrently. Configured producer implementations must satisfy the existing
Producer contract; this operation does not independently validate arbitrary
bytes from a contract-violating implementation.

A nil context or nil source/producer interface is rejected with `record.invalid`.
An invalid DID is rejected before reading. Cancellation observed before/after
source acquisition or between synchronous production calls returns no views and
preserves the cancellation cause under `record.unreachable`. Synchronous calls
cannot be forcibly interrupted by this API. Source failure, mismatched record,
structural/projection error, wrong media type or oversized projection also
returns a nil pair. A second-production error never returns the first view.
This is an all-or-nothing **return-value** guarantee: it does not roll back a
source's durable journal or any earlier observation side effects. No retry or
second observation is attempted to recover a partial pair.

Each document retains its existing size limit; the pair has no aggregate wire
encoding. Created/deactivated records remain inspectable with empty methods and
omitted relationships. Revoked/expired keys remain absent from projections.
Standard `Driver.Read` still returns a null document for a deactivated DID.
Neither successful projection nor the pair grants message authority or proves a
configured deployment's trust policy.

Tests use a changing normal source with complete independently authored document
expectations, exact production options, reusable producer storage, independent
metadata ownership, state/expiry controls and failure/cancellation boundaries.
The complete existing module/standalone race, coverage and owned TLS tests also
run. CI retains focused JSON events, per-function coverage, compiler, public root
module metadata, revision/tree and source hashes. These are bounded library
results, not operating registry qualification or compiled-byte attestation.
