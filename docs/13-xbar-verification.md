# X-bar verification of the design against the specifications

> Run on 2026-10-11 and 2026-10-12. The tooling and its limits are described in
> [`tools/xbar/README.md`](../tools/xbar/README.md).

## 1. Why this check exists

An implementation is written from these documents. A requirement that is
mistranslated, dropped or stated with the wrong strength becomes a defect in
code, and nobody notices until an interoperability failure. The design exists
in two languages (a Korean canonical text and this English translation), and
both restate four W3C documents. Three relations therefore had to be checked:

1. the Korean and English texts say the same thing;
2. each design statement says what the pinned specification says, or says
   openly that it deviates or interprets;
3. each normative specification statement is covered by the design or is
   explicitly out of scope.

## 2. Method

1. **Extraction.** Every sentence with an RFC 2119 keyword and every algorithm
   step was extracted from the pinned publications listed in
   [standards.md](standards.md), after checking their SHA-256: DID Core 1.0
   (206 statements), DID 1.1 (78), Controlled Identifiers 1.0 (179) and DID
   Resolution v1.0 CRD 2026-10-01 (275), 738 in total.
2. **Pairing.** Both language versions were split into units (headings, table
   rows, list items, paragraphs, code blocks) and paired by position inside each
   section. A section whose unit sequence differs means something was added or
   dropped.
3. **X-bar parsing.** Independent parsers turned every unit and every
   specification statement into the same phrase structure: a condition layer
   (CP), the constrained subject (Spec), modality and polarity (T), the
   predicate (V), its object (Comp) and adjuncts. The Korean parsers never saw
   the English text and the English parsers never saw the Korean text, so a
   translation that changes meaning yields structures that differ.
4. **Comparison and graph.** The structures were joined into one graph (units,
   claims and specification statements, with `translates`, `has-claim` and
   `restates` edges) and compared slot by slot. Differences in normativity,
   modality, polarity, condition count, modality against the linked
   specification statement, and technical tokens in code blocks were HARD;
   wording differences were SOFT.
5. **Adjudication.** Every HARD finding was judged by a reviewer who read the
   original texts. Every normative specification statement that no unit linked
   to was reviewed as COVERED, OUT_OF_SCOPE or GAP. Fixes were applied to both
   languages, Korean first.
6. **Repetition.** After each fix round the documents were paired again, units
   whose text changed were parsed again blind, and the comparison and
   adjudication were repeated. Later rounds added a reviewer that had not seen
   the documents before, and targeted checks of the rules changed in the
   previous round.

All 46 Mermaid diagrams (23 per language) were rendered with mermaid-cli
without errors, and every Go block is identical in both languages once
comments are removed.

## 3. Results by round

| Round | Unit pairs | Units re-parsed | Defects found |
|---|---:|---:|---|
| 1 | 1,017 | all 793 prose units, both languages | 259 HARD findings in 146 units: 3 defects (1 translation, 2 specification). Coverage: 361 unlinked statements, of which 47 were gaps. 64 code blocks: no defect, 1 wrong citation. |
| 2 | 1,052 | 84 | 5 in changed prose, 4 in changed code, about 10 contradictions between documents introduced by the fixes. All 47 gaps confirmed fixed. |
| 3 | 1,056 | 32 | No translation defect. 11 contradictions between documents. |
| 4 | 1,059 | 9 | No defect from the parse comparison. A first-time reviewer found 8 (1 high, 3 medium, 4 low). |
| 5 | 1,064 | 17 | No defect from the parse comparison. A targeted check found 18 places where a changed rule had not reached every document. |
| 6 | 1,066 | 23 | A targeted check found 7 small defects (dependency text, two missing diagram branches, one missing Korean sentence, one misattributed source, one code/text mismatch). |

Every finding above was fixed in both languages. The structure stayed aligned
in every round (0 misaligned sections).

## 4. What the check changed

The defects that would most likely have reached code:

- **Representation selection.** DID Core 1.0 and DID 1.1 both say "A
  conforming consumer MUST determine the representation of a DID document using
  the Media Type input string." An intermediate version of the design let the
  first `@context` value override the declared media type. The rule now follows
  the MUST; payload inspection is used only for low-precision media types.
- **Key material.** The design required exactly one of `publicKeyJwk` and
  `publicKeyMultibase`. The specifications make each optional and forbid two
  properties for the same material. The rule is now at most one public and at
  most one secret key property, with presence decided by the type.
- **Verification method type.** The design accepted only `Multikey` and
  `JsonWebKey`. The specifications define those two but do not forbid other
  types, so valid DID Core 1.0 documents would have been rejected.
- **Algorithms.** The CID fragment resolution steps never stored the match, so
  the algorithm as written always returned null. The dereference algorithm left
  out the error results, the endpoint list construction and the relative
  reference rule, and `expandRelativeUrls` was broader than the specification.
- **Resolution results.** `contentType` now always names the media type of the
  bytes returned. Option checks, driver metadata validation and the
  `INTERNAL_ERROR` path were added, and the HTTP status order prevents an
  extension from overriding a status the binding table fixes.
- **Timing and precision.** `expires` and `revoked` apply at or after the given
  time (the English translation had said "after"), and all datetimes follow the
  UTC, whole-second format.
- **Translation.** One unit in Korean lacked a modal that the English and the
  specification have, one Korean sentence was missing, and one package tree
  still used the old module name.

## 5. Recorded deviations and interpretations

The design keeps these on purpose and says so where they apply: the tensions
T1 to T7 in [08](08-verification-report.md); the deviation DEV-V10-1 for the
v1.0 `resolveRepresentation` of a deactivated DID ([09](09-v1.0-compat.md)
§6.1); and the did-go policies and interpretations labelled in
[07](07-did-resolution-contract.md) and
[12](12-standard-core-and-sage-extension.md): reading a present `@context` in
`application/did` as JSON-LD intent, `FEATURE_NOT_SUPPORTED` for an
unsatisfiable `accept`, validation of driver metadata, rejection of
non-canonical `versionTime` values, and `Refines` for the CID errors.

## 6. Limits and remaining risk

- The parsers and reviewers are language models. Their output was treated as
  evidence and every defect was confirmed against the quoted specification
  text, but a defect that no parser or reviewer noticed can remain.
- Each first-time or targeted review still found something, although the
  severity fell from violations of a specification MUST in round 1 to wording
  and diagram gaps in round 6. This check lowers the risk; it does not prove
  that no defect is left.
- DID 1.1 is a Candidate Recommendation and DID Resolution a Candidate
  Recommendation Draft. A new publication requires another run.
- The extractor can split a sentence at an "OR" line, and condition-only
  algorithm steps depend on the parser to carry the condition to child steps.
- No code exists yet. The W3C test suites and the conformance vectors in
  [10](10-abnf-appendix.md) will be the next independent check once the
  packages are implemented.
