# Appendix: Full ABNF, Test Vectors and Assets (Portable Appendix)

> Purpose: fix in one place the parser reference (the full ABNF), the conformance test vectors and the required assets (context files and hashes), so that the `docs/` folder is **implementable on its own** without a clone of the specification repositories.
> The ABNF is **identical in DID Core v1.0 and v1.1** (`09` §2.1). The text below is the shared reference for both versions.
> Original source: quoted verbatim from DID Core v1.1 CR (`w3c/did@13626ba6aac9`) §DID Syntax and §DID URL Syntax. For the full list of source references, see the [README provenance](README.md#provenance) table and [standards.md](standards.md).

---

## 1. Full ABNF (parser reference)

### 1.1 DID (§DID Syntax)

```abnf
did                = "did:" method-name ":" method-specific-id
method-name        = 1*method-char
method-char        = %x61-7A / DIGIT
method-specific-id = *( *idchar ":" ) 1*idchar
idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
pct-encoded        = "%" HEXDIG HEXDIG
```

### 1.2 DID URL (§DID URL Syntax)

```abnf
did-url = did path-abempty [ "?" query ] [ "#" fragment ]
```

### 1.3 Referenced productions (RFC 3986 / RFC 5234, cited by did-url)

```abnf
; RFC 3986
path-abempty  = *( "/" segment )
segment       = *pchar
pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
query         = *( pchar / "/" / "?" )
fragment      = *( pchar / "/" / "?" )
unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
              / "*" / "+" / "," / ";" / "="

; RFC 5234 core
ALPHA         = %x41-5A / %x61-7A   ; A-Z / a-z
DIGIT         = %x30-39             ; 0-9
HEXDIG        = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
```

**Implementation notes**
- `method-specific-id` allows a multi-level structure separated by colons (`*( *idchar ":" ) 1*idchar`). However, **the last character must be an idchar** (no trailing colon, no empty msid).
- HEXDIG in `pct-encoded`: RFC 3986 §2.1 recommends uppercase when encoding and treats case as insignificant when interpreting. The parser accepts both. Normalized output should use uppercase.
- **Scheme case**: in RFC 5234 the string literal `"did:"` is formally case-insensitive, but every example in the specification and the test suite practice use lowercase `did:`. **This implementation accepts lowercase only** (strict). Lenient input (`DID:`) is accepted only through a normalization option (see the note case in §2.1).
- The semicolon (`;`) is valid inside path and query as a `sub-delims` character, but its use as a DID parameter separator is reserved for the future. It triggers a warning (FR-S2).
- In a pure DID context (subject, controller), `?` and `#` are prohibited (§Identifier Restrictions, FR-S6). Note that the `did` production itself has no path, query or fragment.

---

## 2. Test vectors (conformance corpus)

### 2.1 DID syntax: valid (Parse succeeds)

| # | Input | What it checks |
|---|-------|----------------|
| V1 | `did:example:123456789abcdefghi` | Basic form |
| V2 | `did:example:123` | Short msid |
| V3 | `did:0abc:xyz` | DIGIT allowed in method-name |
| V4 | `did:example:123:456:789` | Multi-level colon structure in msid |
| V5 | `did:web:w3c-ccg.github.io` | `.` in idchar |
| V6 | `did:web:example.com%3A8080` | pct-encoded (`%3A`=`:`) |
| V7 | `did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu` | Real did:key form |
| V8 | `did:example:a-b_c.d` | Combination of `-` `_` `.` in idchar |

### 2.2 DID syntax: invalid (Parse fails and reports the position)

| # | Input | Reason for failure |
|---|-------|--------------------|
| I1 | `did:EXAMPLE:123` | method-char is only `%x61-7A` (lowercase) plus DIGIT |
| I2 | `did:example:` | msid must end with `1*idchar` (empty msid) |
| I3 | `did:example:123:` | Trailing colon (last character is not an idchar) |
| I4 | `did::123` | method-name is `1*method-char` (cannot be empty) |
| I5 | `did:example` | Second `:` is missing |
| I6 | `did:example:1%3` | Incomplete pct-encoded |
| I7 | `did:example:1%GG` | Not HEXDIG |
| I8 | `did:ex ample:123` | A space is neither idchar nor method-char |
| I9 | `example:123` | `did:` scheme is missing |
| I10 | (subject/controller context) `did:example:123#key-1` | §Identifier Restrictions: a fragment is prohibited in a pure DID (`ErrIdentifierRestriction`) |

**Note case**: `DID:example:123`. The ABNF literal is formally case-insensitive, but this implementation is strict lowercase (§1.3 implementation notes). Documented as: strict mode = I11 (fails); with the normalization option enabled, the input is lowercased and then accepted.

### 2.3 DID URL: valid (expected component split)

| # | Input | DID | Path | Query | Fragment |
|---|-------|-----|------|-------|----------|
| U1 | `did:example:123/path/sub?versionId=1#key-1` | `did:example:123` | `/path/sub` | `versionId=1` | `key-1` |
| U2 | `did:example:123#keys-1` | `did:example:123` | (empty) | — | `keys-1` |
| U3 | `did:example:123?service=agent&relativeRef=/credentials#degree` | `did:example:123` | (empty) | `service=agent&relativeRef=/credentials` | `degree` |
| U4 | `did:example:123?versionTime=2021-05-10T17:00:00Z` | `did:example:123` | (empty) | `versionTime=…Z` | — |
| U5 | `did:example:123?hl=zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e` | v1.0 `hl` parameter: accepted on the v1.0 path (`09` §6.2), not passed to the core | | | |
| U6 | (relative reference) `#key-1` + base `did:example:123` | → `did:example:123#key-1` (made absolute per RFC3986 §5) | | | |
| U7 | `did:example:123/` | `did:example:123` | `/` | — | — (path-abempty allows an empty segment) |

### 2.4 DID URL: invalid

| # | Input | Reason for failure |
|---|-------|--------------------|
| IU1 | `did:example:123##frag` | `#` is not allowed inside a fragment (not in the fragment production) |
| IU2 | `did:example:123?q=^v` | `^` is not a pchar or query character |
| IU3 | `did:EXAMPLE:123/path` | If the DID part is invalid, the whole URL is invalid |

### 2.5 Version detection vectors (every row of the precedence table in `09` §4)

| # | Media type | `@context[0]` | Expected result |
|---|------------|---------------|-----------------|
| D1 | `application/did+json` | (none) | **V10** (rule 1) |
| D2 | `application/did+ld+json` | `…/did/v1` | **V10** (rule 1) |
| D3 | `application/did` | `…/did/v1` | **V10** (rule 2) |
| D4 | `application/did` | `…/did/v1.1` | **V11** (rule 3) |
| D5 | `application/did` | (none) | **VUnknown** → consumed with v1.1 rules (rule 4) |
| D6 | `application/did+json` | `…/did/v1.1` | **V10** (rule 1 wins; checks that the precedence is fixed) |

### 2.6 Document conformance vectors

**C1: valid v1.1 document** (v1.1 CR §A simple DID document example, normalized with comments removed):
```json
{
  "@context": "https://www.w3.org/ns/did/v1.1",
  "id": "did:example:123456789abcdefghi",
  "authentication": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Multikey",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
  }]
}
```

**C2: valid v1.0 document** (v1.0 REC Example 1, comments removed and normalized):
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "authentication": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}
```
- Consumption: **detected as V10, then normalized into the single core model successfully** (FR-V2). The `Ed25519VerificationKey2020` type is not defined by CID, but consuming it is not an error (it is an extension type; if no codec is registered, it is only treated as unverifiable).

**C3: invalid, both key materials present** (CID §2.2.1 MUST NOT → `ErrKeyFormatConflict`):
```json
{ "id": "did:example:1", "verificationMethod": [{
  "id": "did:example:1#k1", "type": "Multikey", "controller": "did:example:1",
  "publicKeyMultibase": "z6Mk…", "publicKeyJwk": {"kty": "OKP"} }] }
```

**C4: invalid, root is not an Object**: `[ {"id": "did:example:1"} ]` → `ErrNonConforming`.

**C5: invalid, private member in JWK**: `publicKeyJwk: {"kty":"OKP","crv":"Ed25519","x":"…","d":"…"}` → prohibited by CID (`06` §6).

**C6: V10 production profile**: a document with `service: [{"type":"A","serviceEndpoint":"https://e.example"}]` (no id) → **V11 production succeeds, V10 production is rejected** (`ConformanceError`, FR-V3, ADR-13).

**C7: rule 4 round-trip preservation**: a document containing the unrecognized property `"fooExtension": 42` → after consumption it is present in `Document.extensions`, and on re-production it is preserved in place (FR-D7, prevents regression of M3).

**C8: deactivated is not an error**: a resolve result with `didDocument=null` and `didDocumentMetadata.deactivated=true` → no error. The v1.0 adapter path also keeps `error=""` (`09` §6.1).

---

## 3. Assets (assets/): context files and pinned integrity values

| File | Target URL | SHA-256 | Source and status |
|------|------------|---------|-------------------|
| [`assets/did-v1.jsonld`](assets/did-v1.jsonld) | `https://www.w3.org/ns/did/v1` | `4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad` | **Hash confirmed to match the official published file** (2026-07-22, identical to `curl https://www.w3.org/ns/did/v1`) |
| [`assets/did-v1.1.jsonld`](assets/did-v1.1.jsonld) | `https://www.w3.org/ns/did/v1.1` | `ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85` | Snapshot of `context/v1.1rc1` from `w3c/did@13626ba6aac9`. **Note: that URL is not yet published (300 response, CR stage).** It must be re-pinned when v1.1 is published as a REC. |

- The implementation embeds these two files with `go:embed` and verifies them against the hashes above at load time (FR-R6/FR-V5, `05` §4).
- The v1.1 value is updated when the specification is finalized, using `curl -s https://www.w3.org/ns/did/v1.1 | openssl dgst -sha256` (the check procedure in v1.1 §Remote Resource Integrity). **Until it is re-pinned, it is tracked as a release-blocking item.**

---

## 4. Test mapping

| Vector group | FRs verified | Related documents |
|--------------|--------------|-------------------|
| §2.1–2.2 | FR-S1, S4, S5 | `00` §2.1, `04` §2 |
| §2.3–2.4 | FR-S2, S3, S6 | `02` §1, `07` §3 |
| §2.5 | FR-V1, V2 | `09` §4 |
| §2.6 C1–C5 | FR-D3, D7, R2, P3 | `06` §2, §6 |
| §2.6 C6 | FR-V3 | `09` §5, ADR-13 |
| §2.6 C7 | FR-D7 | `08` §3 regression item (b) |
| §2.6 C8 | FR-X4, V4 | `07` §1.1, `09` §6.1 |
| §3 | FR-R6, V5 | `05` §4 |
