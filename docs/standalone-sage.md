# Standalone SAGE module compatibility

`advanced/sage` is an optional module. The standard root module does not import
it. Its public root dependency is pinned to
`v0.0.0-20261018080828-3b7a79c1c326` (commit
`3b7a79c1c326a648b283ac4ccf35c691fabf053c`), with module checksum
`h1:Am4pVUAnGnhje6WZgO19ltbRV1NDCfvmEzQAuwHInM8=`.
There is no `replace` directive. Existing SAGE 0.10.0 projection and error
contracts are unchanged.

The repository workspace selects the local root and extension together. It
cannot prove that the extension builds with its declared public dependency.
The separate `standalone-sage` CI job uses Go 1.26.8 and `GOWORK=off` throughout.
It checks the selected version, both checksums and absence of replacement,
verifies the module cache, builds the extension, runs vet and lint, and runs the
entire extension suite with the race detector and at least 90% statement coverage.
Module files must remain unchanged. The artifact retains the module graph,
compiler, checkout revision/tree, source hashes, test events and coverage.
This is build and runtime compatibility evidence, not compiled-byte attestation.

`TestStandaloneSAGETLS` checks ten cases through both GET and POST clients:
Core 1.0 and DID 1.1 document projections, a full result envelope, signing-key
and absent-key fragments, absent and stale records, invalid active records,
created records and deactivated records. Each case makes exactly one HTTP
request over owned loopback TLS and one in-memory Source observation. The
existing suite also exercises direct library calls and projection bytes.
No external registry, blockchain transaction, signing service or attack
reproduction is involved.

## Consumer migration boundary

A downstream module keeps selecting its own recorded versions until it updates
its dependency graph. This extension update does not adopt the new root in Go
SAGE, Rust, ADK or Inspector. Historical Inspector subjects and reports remain
pinned and must not be combined with this compatibility run. A future consumer
update must verify its selected root and extension versions without a workspace
or replacement, then exercise its actual public entry points and trust boundary.

The active envelope's explicit metadata requirements and the two existing DIDP
failures remain separate work. The algorithm, key identifier and JSON-LD
recommendations remain tracked under the approved SAGE 0.10.0 policy; this update
does not change projection policy or claim complete standards conformance.
See [the root/extension contract](12-standard-core-and-sage-extension.md) and
[the DID Resolution contract](07-did-resolution-contract.md) for the dated
specifications and existing behavior.
