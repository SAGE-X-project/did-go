# Pinned standards

The design follows these dated W3C publications. Each SHA-256 is of the HTML
bytes served at the dated URL on the download date. To re-check, fetch the
dated URL and compare with `shasum -a 256`. A newer publication is added as a
new row together with the design changes it causes; existing rows are not
overwritten.

| Document | Status | Date | Dated URL | SHA-256 |
|---|---|---:|---|---|
| DID Core 1.0 | W3C Recommendation | 2022-07-19 | https://www.w3.org/TR/2022/REC-did-core-20220719/ | `5e44345740d9bfaa852d3b66c57e98c9beb6c5bf6083b0126dd5daac377b9993` |
| DID 1.1 | W3C Candidate Recommendation Snapshot | 2026-03-05 | https://www.w3.org/TR/2026/CR-did-1.1-20260305/ | `4a48022defe07d37d2decc3ec9027a932dc883b2ad164a5aeaf9256e530bd979` |
| Controlled Identifiers 1.0 | W3C Recommendation | 2025-05-15 | https://www.w3.org/TR/2025/REC-cid-1.0-20250515/ | `c5e9befba602b53de46669cf98067123d1901357a425f8bff621796b2ac4ac4a` |
| DID Resolution v1.0 | W3C Candidate Recommendation Draft | 2026-10-01 | https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/ | `2b194843d37f5b7f01a4f5464f64d672dc4be43dafe5f2f49114c6070819586e` |
| DID Resolution v1.0 (superseded) | W3C Candidate Recommendation Draft | 2026-08-28 | https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20260828/ | `def1bf7cdcd38d712d52cb38d8bda538fff9f29fa5201e5d737d7efc073c79f1` |

The DID Resolution 2026-10-01 draft was downloaded on 2026-10-11; the others on
2026-08-28. The only normative change from 2026-08-28 to 2026-10-01 is in error
handling: an error type outside the HTTPS binding table now gets an
implementation-chosen status instead of 500, and a specification may declare
that its error type refines a core error type (see 07).

W3C Credentials Community Group method specifications, pinned by repository
commit (they have no dated publications); the SHA-256 is of `index.html` at
that commit:

| Document | Status | Commit date | Pinned revision | SHA-256 |
|---|---|---:|---|---|
| did:key | CG draft | 2025-11-02 | https://github.com/w3c-ccg/did-key-spec/blob/2cc490c38c5aacf58497a87fc0cf8794668bf716/index.html | `e014a146acb0dcdafbdfee01226061d778da3ee72e8a048a7d53754c79675764` |
| did:web | CG draft | 2026-05-08 | https://github.com/w3c-ccg/did-method-web/blob/ea423c114e6f2537498ee6f94e8d794c64f60c18/index.html | `7e48b1ad2d658452bc9ce23b975d243abe095f7696c06671fc332705a1290610` |

Other references: RFC 3986, RFC 5234, RFC 7515, RFC 8785, RFC 9457 and RFC 9864.

The copyright and terms of use of each W3C document follow the
[W3C Document License](https://www.w3.org/copyright/document-license/). This
repository's license does not apply to them.
