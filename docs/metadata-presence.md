# Metadata boolean presence

DID Resolution, Candidate Recommendation Draft of 1 October 2026,
[proxied resolution](https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/#resolver-architectures-proxied),
recommends transparent preservation of upstream resolution and document metadata.
An absent `deactivated` member and an explicit `false` remain distinct.

`document.Metadata.Deactivated` remains a boolean. Existing true assignments
are still serialized. Set `DeactivatedPresent: true` when constructing metadata
that must include false. JSON decoding records presence for either boolean;
cloning preserves it, and `IsEmpty` treats explicit false as a property.
The zero value still serializes to `{}`. Null and other non-boolean values
are rejected without replacing the destination. This flag does not establish
that the record is active or that upstream data is authoritative.

The SAGE authoritative projector must eventually set presence for created,
active and deactivated records, as RESOLVE-03 requires. That adoption is
separate: publish the repaired root module and update the advanced module
dependency before using the new field with GOWORK=off. This change does not
update the advanced projector or existing SAGE consumer pins. The previous
SAGE envelope findings remain unresolved. Generic metadata does not gain
an unconditional false default. Old inspection reports remain separate evidence.

Tests exercise absent/false/true serialization, cloning, reuse and invalid
input, plus two owned loopback TLS proxy hops preserving structural proofs
and extension maps. These public fixtures do not verify proof signatures,
registry authority, or deployment security.
