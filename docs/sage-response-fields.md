# SAGE response fields

The adopted SAGE 0.10.0 chapter 10 at commit
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b` requires the `deactivated`
boolean in RESOLVE-03 metadata, including `false` for active and created
records. `sage.Metadata` now sets `DeactivatedPresent` so both SAGE envelopes
and DID Resolution responses carry that value. The generic root
`document.Metadata{}` continues to omit an absent member. Deactivation and
message authorization policy are unchanged.

DIDP-05 requires `sageCode: representation.unsupported` when the DID
Resolution interface cannot serve a requested representation. The SAGE wrapper
now reports that code only for the root resolver's typed Accept refusal on a
`did:sage` DID. It preserves the original error, its negotiation marker and the
DID Resolution status/type. Unknown extension options, malformed Accept values,
other DID methods and handler method/TLS refusals are not relabeled.
The SAGE interface's exact-media selection table remains separate.

The applicable binding follows the dated DID Resolution 1.0 CRD 2026-10-01
sections 4.4 and 12.1, as recorded in [the resolution contract](07-did-resolution-contract.md).
No new profile, algorithm policy or trust source is introduced. Historical
Inspector subjects keep their original findings; a new public dependency pin
and separate runtime report are required to assess these fixes.
