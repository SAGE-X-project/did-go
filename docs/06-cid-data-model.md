# CID 1.0: Data Model Rules and Go Mapping

> Source: `cid/index.html` (W3C Controlled Identifiers v1.0, [w3c/cid](https://github.com/w3c/cid) @ `2b962ac29e13`; line numbers in this document refer to that commit). See [standards.md](standards.md). Context `https://www.w3.org/ns/cid/v1`, vocabulary namespace `https://w3id.org/security#`.
> Role: DID Core v1.1 delegates the VM, Service and Relationship data models to this specification. This document fixes the **exact rules** that the `vm` and `crypto` packages in `05-go-design.md` must implement.
> Boundary: `equivalentId` and `canonicalId` belong to **DID Core (didDocumentMetadata)**, not to CID. See `07-did-resolution-contract.md`. CID defines only `id` (the base identifier) and the `canonical URL`.

---

## 1. Controlled Identifier Document core model (§2.1)

| Property | Required | Type / cardinality | Rule |
|----------|----------|--------------------|------|
| `id` | **yes** | URL string | MUST be present in the top-level map (§2.1.1 line 785). On dereference, the returned document's base identifier MUST be the same as the canonical URL, and only then is the document authoritative. On mismatch, the returned document is not authoritative and the **identifier SHOULD be treated as invalid** (line 808-812). |
| `controller` | no | string or set of strings (each a URL) | Each entry must identify an entity that can update the canonical document (line 894). If absent, the storage location determines control (line 901). |
| `alsoKnownAs` | no | set of URIs (RFC3986) | Equivalence may be inferred only when the relationship is **reciprocal**. |
| `service` | no | set of service maps | §7 |
| `verificationMethod` | no | set of VM maps | §2 |
| `authentication` / `assertionMethod` / `keyAgreement` / `capabilityInvocation` / `capabilityDelegation` | no | set of (URL string or VM map) | §6 |

**Conformance (§conformance):** "Conforming processors **MUST produce errors when non-conforming documents are consumed**" (line 461). This is a hard requirement on consumers.

---

## 2. Verification Method (§2.2)

A VM map **MUST contain** `id`, `type`, `controller`, plus the verification material that `type` defines (line 1147). Additional properties are allowed (MAY; DID Core 1.0 §5.2 says the same). `vm.Method` keeps every property it does not model in an `Extra` map. The Consumer fills the map, the Producer writes it back unchanged, and a VM is never rejected only because it has additional properties.

| Property | Required | Type / constraint |
|----------|----------|-------------------|
| `id` | **yes** | URL string. The verification method identifier. |
| `type` | **yes** | String that references exactly one VM type (MUST). CID defines the types `Multikey` and `JsonWebKey` but does not forbid other types. DID Core 1.0 §5.2 only recommends that the type be registered in the DID Specification Registries (SHOULD), so other types such as `Ed25519VerificationKey2020` and `JsonWebKey2020` are in use. did-go fully validates `Multikey` and `JsonWebKey`. Other types get only the generic form checks (§5). Such a type is not used to verify proofs unless a codec is registered for it. |
| `controller` | **yes** | URL string. **Not necessarily the same as the document's controller.** It is only a *claim* and can be false (line 1245). Binding is established only by the algorithm in §3. |
| `expires` | no | XSD `dateTimeStamp` string. |
| `revoked` | no | XSD `dateTimeStamp` string. |
| Verification material | conditional | `publicKeyJwk` / `publicKeyMultibase` / `secretKeyJwk` / `secretKeyMultibase` (chosen by type). |

### 2.1 Verification material is mutually exclusive (§2.2.1, line 1306). Core rule.
> **"A verification method MUST NOT contain multiple verification material properties for the same material. ... expressing key material ... using both `publicKeyJwk` and `publicKeyMultibase` at the same time is prohibited."**

Key conversion is allowed, but it **must not change the external representation** (line 1313).

This rule forbids expressing the same material with two properties. It does not forbid a VM with no material property. The three specifications say the following.
- DID Core 1.0 §5.2.1: `publicKeyJwk` and `publicKeyMultibase` are each OPTIONAL. `type` determines which material properties the VM map carries. A VM MUST NOT contain more than one material property for the same material.
- CID §2.2.2, §2.2.3: Multikey's `publicKeyMultibase` and `secretKeyMultibase`, and JsonWebKey's `publicKeyJwk` and `secretKeyJwk`, are all OPTIONAL. A public key and a secret key are different material, so `publicKeyMultibase` and `secretKeyMultibase` may appear together.
- DID 1.1 §5.2: delegates VM rules to CID §2.2 and only adds the `id` (DID URL) and `controller` (DID) constraints. Its property table also marks `publicKeyMultibase` and `publicKeyJwk` as not required.

So did-go allows at most one public key material property (`publicKeyJwk` together with `publicKeyMultibase` is an error). The same holds for secret material: `secretKeyJwk` together with `secretKeyMultibase` is an error. A VM without public key material is accepted as conforming, but it cannot be used to verify a proof.

### 2.2 Consuming expires and revoked (§2.2, Security §5)
- `expires`: after the expiry **time**, proofs linked to that VM are **expected not to be verified** (line 1182). Once set, it is not updated.
- `revoked`: the VM MUST NOT be used **after** the given time (line 1197).
- Revocation and expiry are **not retroactive**. They apply only to the latest document version (§Revocation Semantics line 3348). If a verifier cannot reliably determine the document state and time, it is safe to consider **only the current state**.

---

## 3. Retrieve Verification Method algorithm (§3.3): two-way binding

Input: `vmIdentifier`, `verificationRelationship`, `options`. Output: a VM. Each step raises a named error.

```
1. vmIdentifier is not a valid URL          → INVALID_VERIFICATION_METHOD_URL
2. controllerDocumentUrl = vmIdentifier with the fragment removed
3. vmFragment = fragment of vmIdentifier
4. controllerDocument = dereference(controllerDocumentUrl)
5. not a conforming CID document            → INVALID_CONTROLLED_IDENTIFIER_DOCUMENT
6. controllerDocument.id != controllerDocumentUrl → INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID
7. verificationMethod = dereference(vmFragment) within controllerDocument
8. not a conforming VM                      → INVALID_VERIFICATION_METHOD
9. abs(verificationMethod.id) != vmIdentifier         → INVALID_VERIFICATION_METHOD
10. abs(verificationMethod.controller) != controllerDocumentUrl → INVALID_VERIFICATION_METHOD
11. VM is not associated (by reference or by value) with the verificationRelationship array
                                            → INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD
12. return verificationMethod
```

This algorithm enforces a two-way binding: **document to VM (through the relationship)** and **VM to document (through `controller`)**. It supports **external VMs** (VMs that live in another document, for example `capabilityInvocation: ["https://external.example/xyz#key-789"]`).

## 4. Fragment Resolution algorithm (§3.4): for `application/cid`

```
Input: document (map), fragmentIdentifier (string)
1. documentFragment = null
2. canonicalDocumentUrl = document.id
3. fullyQualifiedFragment = canonicalDocumentUrl + fragmentIdentifier
4. Recursively scan every map in document; at the first map whose
   id == fullyQualifiedFragment or id == fragmentIdentifier, set documentFragment to that map and stop
5. return documentFragment  (null if none)
```
Duplicate fragments with the same id lead to undefined behavior (avoid them). Fragment rules for `application/did` documents may differ (JSON-LD rules).

---

## 5. Multikey (§2.2.2): Go `vm` prefix table and `crypto` codecs

`type == "Multikey"`. `publicKeyMultibase` / `secretKeyMultibase` are Multibase (**base58-btc, header `z`**) = `z` + base58btc(multicodec varint prefix ‖ raw key bytes).

**Public key multicodec prefixes (the prefix is a MUST in every row; the following base-58-btc encoding sentence lacks MUST only in the P-384 row, which says "is then encoded"):**

| Key type | 2-byte prefix | Raw bytes | Total length |
|----------|---------------|-----------|--------------|
| Ed25519 | `0xed01` | 32 | 34 |
| ECDSA P-256 | `0x8024` | 33 (compressed) | 35 |
| ECDSA P-384 | `0x8124` | 49 (compressed) | 51 |
| BLS12-381 G2 | `0xeb01` | 96 | 98 |
| SM2 | `0x8624` | 33 | 35 |
| X25519 (outside CID 1.0, used by did:key) | `0xec01` | 32 | 34 |

**Secret key prefixes:** Ed25519 `0x8026` (34), P-256 `0x8626` (34), P-384 `0x8726` (50), BLS12-381 G2 `0x8030` (98), SM2 `0x9026` (34).

The BLS12-381 G2 secret key row gives the prefix `0x8030` and calls it "the varint expression of 0x130a", but the varint of `0x130a` is `0x8a26`. `vm` therefore accepts both `0x8030` and `0x8a26` as the secret key prefix of this key type (`08` T9). did-go produces no BLS12-381 secret keys.

- An unknown header, or a value that is not a public key header where a public key is expected, **raises an error** (line 1528).
- **Alternative encodings MUST NOT be defined** for key types that are already defined (line 1537).
- The X25519 row is not in the CID 1.0 table. It is the x25519-pub multicodec (`0xec`, varint `0xec01`) that the did:key specification uses for key agreement methods. CID 1.0 §2.2.2 lets other specifications define header values for other key types, so did-go keeps this row in the `vm` table and validates the X25519 key agreement method that did:key derives. `crypto` uses X25519 keys for key agreement only, never for signature verification.
- The Multibase form of a `publicKeyMultibase` value is checked for every VM type. DID Core 1.0 §5.2.1 requires the value to be a string representation of a Multibase-encoded public key (MUST), and the DID 1.1 property table sets the same constraint. So even for a type other than Multikey (for example v1.0 `Ed25519VerificationKey2020`), a value that is not a string, whose first character is not a Multibase header, or whose header is `z` or `u` but whose remaining characters do not decode in that alphabet, is a conformance error. For type `Multikey` the header MUST be `z`, and any other header is an error, because the CID §2.2.2 public key table encodes each key type with the base-58-btc alphabet and prepends the base-58-btc Multibase header (`z`) (MUST in the P-256, Ed25519, BLS12-381 and SM2 rows; the P-384 row states the same with "is then encoded"). Accepting other headers that did-go cannot decode, with a warning, applies only to types other than `Multikey`, and such values are not used to verify proofs. A type with no registered codec, whose key bytes did-go cannot interpret, still goes through the form check.
- A present but empty `publicKeyMultibase` or `secretKeyMultibase` (`""`) is an error. CID §2.2.2 says "If present, its value MUST be a Multibase encoded value", and a Multibase value has at least its one-character header (CID §2.4). `vm.Method` stores `""` as an absent property, so the consumer checks the JSON member itself and returns a `*consumer.Error` citing `cid10#Multikey.3` (`core10#verification-material.7` for a DID Core 1.0 document) or `cid10#Multikey.5`. An empty `publicKeyJwk` or `secretKeyJwk` object (`{}`) has no `kty`, so it is not an RFC7517 JWK and fails `cid10#JsonWebKey.3` or `cid10#JsonWebKey.11` (§6).

## 6. JsonWebKey (§2.2.3)

`type == "JsonWebKey"`.
- `publicKeyJwk`: an RFC7517 JWK map. It **MUST NOT contain private or secret members such as `d`** (line 1569, 1633).
- `kid`: if present, it SHOULD equal `id` or a part of it (path, query or fragment). Using `kid` as the VM fragment is RECOMMENDED. A JWK Thumbprint (RFC7638, SHA-256) as `kid` is RECOMMENDED.
- `alg`: SHOULD be included to prevent misuse across algorithms. `crv` is REQUIRED for EC keys.
- `secretKeyJwk`: **MUST NOT be used** in structures that may be made public. If present, its value MUST be a map that is a JSON Web Key conforming to RFC7517, and the validator rejects any other value.

---

## 7. Verification Relationships (§2.3)

General rule: a VR expresses that "one or more VMs are **authorized to verify proofs on behalf of the subject**". A verifier must check that the VM used **is referenced from the relevant relationship property** (line 1724). A VM that is not in a relationship **cannot be used** for that relationship (line 1730). If a referenced VM is not in the latest document, it is **treated as invalid or revoked** (line 1741).

Each relationship is OPTIONAL. Its value is **a set of one or more VMs**. Each element is either embedded (a map) or referenced (a URL string).

| Relationship | Meaning |
|--------------|---------|
| `authentication` | Authentication (login, challenge-response). Used only to authenticate on behalf of the base identifier. |
| `assertionMethod` | Expressing assertions or claims (for example, issuing VCs). |
| `keyAgreement` | Encryption and secure channel establishment. |
| `capabilityInvocation` | **Authorization**: invoking capabilities (updating the document, accessing protected APIs). |
| `capabilityDelegation` | **Authorization**: delegating capabilities (ZCAP, UCAN). |

Authentication versus authorization: `authentication` ("who are you?") is not the same as `capabilityInvocation` / `capabilityDelegation` ("are you allowed?"). Using **different VMs** for them is recommended.

**VMs in DID controller documents (DID Core 1.0 §5.1.2, SHOULD):** when a DID document has a `controller` property, the VMs contained in the DID documents of those controller DIDs SHOULD be accepted as authoritative for the subject. A proof that satisfies such a VM is treated as equivalent to a proof provided by the DID subject. The same section also says the controller documents SHOULD contain verification relationships that state which VMs may be used for which purposes. This sentence exists only in v1.0. DID 1.1 §5.1.2 delegates the controller definition to CID §2.1.2, and CID has no such sentence. So did-go supports this lookup only for DID Core 1.0 documents (requirement `core10#did-controller.4`). The pure selector `document.SelectMethod` looks only inside the subject document (`05` §3.5). The lookup is done by the `relyingparty` player. `RelyingParty.VerificationMethod` runs the CID Retrieve VM algorithm of §3 over a `resolution.Dereferencer`: it dereferences the document URL without the fragment, refuses a deactivated DID and a document that does not conform or whose `id` is not that URL, and leaves the remaining steps to `document.SelectMethod`. A revoked or expired VM is refused as well (CID §2.2). `VerificationMethodFor(subject, ref, p)` also checks that the VM speaks for the subject: ref must be a VM of the subject's own document. With `WithControllerDocuments()` and a DID Core 1.0 subject document, a VM in the document of a DID listed in the subject's `controller` is accepted too, and that VM must then be in verification relationship p of the controller's document. The option is opt-in. The subject document's version is set with `WithVersion`, or else taken from the detection result of the resolver given with `WithResolver`. `relyingparty.New` returns an error for `WithControllerDocuments()` when the DID Core 1.0 profile can never apply (another version is set, or there is neither a version nor a resolver).

## 8. Service (§2.1.4)

Each service map **MUST contain** `type` and `serviceEndpoint`. `id` is OPTIONAL in the sub-definition, but **services with the same `id` MUST NOT be duplicated** (line 1057).

| Sub-property | Required | Constraint |
|--------------|----------|------------|
| `id` | (conditional) | A URL if present. Must not be duplicated within the document. The DID 1.1 property table allows a URL or a DID. |
| `type` | **yes** | string or set of strings. |
| `serviceEndpoint` | **yes** | a single string, a single map, or a set of strings and maps. **Each string MUST be a valid URL** (line 1072). |

> Tension inside the specification: the parent sentence makes `id` required, while the sub-definition makes it optional. The validator follows the sub-definition (the more specific one) but raises a warning flag.

**Additional properties (CID §2.1.4, DID Core 1.0 §5.4, MAY):** a service extension MAY include additional properties and MAY further restrict the properties associated with the extension. `vm.Service` keeps every property other than `id`, `type` and `serviceEndpoint` in an `Extra` map. The Consumer fills it and the Producer writes it back unchanged.

**Version differences (DID Core 1.0 §5.4):** the table above gives the CID and DID 1.1 rules and applies to V11 validation (`document.Validate(d, spec.V11)`). In V10 validation (`document.Validate(d, spec.V10)`), and when consuming a document detected as V10, the v1.0 rules apply.
- `id` is required and MUST be a URI conforming to RFC 3986, of any scheme. For example `urn:uuid:…` is accepted. A producer MUST NOT produce multiple services with the same `id`, and a consumer MUST produce an error if it detects such a duplicate.
- Every string value of `serviceEndpoint` MUST be a valid URI conforming to RFC 3986 and normalized per RFC 3986 §6 (Normalization and Comparison) and the normalization rules of its scheme specification. `document.Validate(d, spec.V10)` reports a string that is not a valid URI or is not normalized as an error finding (`SeverityError`). CID and DID 1.1 require only a valid URL per the URL Standard and do not require normalization.

---

## 9. Multibase and Multihash data types (§2.4)

- **Multibase** (§`#multibase-0`): `z` means base58-btc, `u` means base64-url-no-pad. On encoding, the header character MUST be prepended. On decoding, everything after the first character is Base Decoded with the corresponding alphabet. Both headers use the CID §3.1/§3.2 integer base-conversion algorithm, which for `u` differs from RFC 4648 bit packing (tension T8 in `08`).
  - Encoding and decoding MUST apply CID §3.1 Base Encode and §3.2 Base Decode (§2.4). Another algorithm with the same output MAY be used (§2.4 and the §3 introduction). Both algorithms use integer arithmetic only, and each leading zero byte maps to one leading first-alphabet character and back on decoding. did-go may use a vetted base58btc or base64url library, and tests compare its output with the CID examples. The other §3 algorithms (Retrieve VM, Fragment Resolution) may also be implemented differently as long as the output is the same.
- **Multihash** (§`#multihash`): varint(header) ‖ varint(length) ‖ digest. For example `sha2-256` = `0x12` (32 bytes).
  - To decode, remove the varint header (hash algorithm) and the varint digest length, then extract the digest (MUST, §2.5). The digest length MUST equal both the output length of the algorithm the header names and the length written in the value. Otherwise the value is rejected.
- `multibase` RDF data type URL: `https://w3id.org/security#multibase`.

## 10. Context and media type

- JSON-LD Context URL: `https://www.w3.org/ns/cid/v1` (pinned by SHA-256). During JSON-LD processing it MUST be treated as already resolved (line 2866).
- **Context Injection** (line 2917): if `@context` is missing or a term is unmapped, `https://www.w3.org/ns/cid/v1` (or the DID v1.1 context) MUST be injected or added.
- Not using JSON-LD is allowed (MAY). The meaning is the same.
- Media type **`application/cid`** (§IANA): follows the `application/json` encoding rules.

---

## 11. Go mapping summary (generic CID layer; relationship to `05-go-design.md` §3.3)

> Generic CID documents also allow controllers that are not DIDs, but did-go's `vm.Method` has only the type-enforced form of **`05` §3.3** (`ID did.DIDURL` / `Controller did.DID`). The mapping below copies the shape of that code, and there is no separate string URL form.

```go
// vm.Method (CID §2.2): id is a did.DIDURL (a relative DID URL is allowed in DID 1.1), controller is a did.DID
type Method struct {
    ID         did.DIDURL // DID URL or relative DID URL
    Type       string     // exactly one VM type. Multikey and JsonWebKey: full validation; other types: generic form checks only
    Controller did.DID    // only a claim; document.SelectMethod (the Retrieve algorithm) checks the binding
    Expires    *time.Time // XSD dateTimeStamp
    Revoked    *time.Time
    // Public key material: each OPTIONAL, never both (§2.1). Without it the VM cannot verify proofs
    PublicKeyMultibase string
    PublicKeyJwk       map[string]any
    // Secret material: excluded from serialization by default. Never both either
    SecretKeyMultibase string
    SecretKeyJwk       map[string]any
    // Additional properties that are not modeled (§2, MAY). Filled on consume, written back unchanged on produce
    Extra map[string]any
}

// vm.MultikeyCodec: multicodec prefix table (§5). Pure data that uses only the standard library, kept in vm.
// crypto imports vm to use this table. vm does not import crypto (05 §1, §7).
type MultikeyCodec struct {
    Name              string  // key type, for example "Ed25519"
    Prefix            [2]byte // two-byte varint multicodec prefix, for example {0xed, 0x01}
    KeyLength         int     // number of key bytes after the prefix, for example 32
    Secret            bool    // true for a secret key row
    PrefixStatement   string  // requirement id of the prefix and length rule
    EncodingStatement string  // requirement id of the base-58-btc encoding rule; "" for a row stated without MUST
}
func MultikeyCodecs() []MultikeyCodec                                  // public and secret key rows, in a fresh slice
func DecodeMultikey(value string, secret bool) (MultikeyCodec, []byte, error) // checks header z, a prefix of the expected kind and the row's length
func EncodeMultikey(codec MultikeyCodec, key []byte) (string, error)
```

**Hard validator rules (to be turned into tests):**
1. Material properties are chosen by `type` and each is OPTIONAL. Expressing the same material with two properties is an error: `publicKeyJwk` and `publicKeyMultibase` cannot appear together, and neither can `secretKeyJwk` and `secretKeyMultibase`. A VM without public key material is conforming but cannot verify proofs (§2.1).
2. `publicKeyJwk` must not contain private members such as `d`. If `secretKeyJwk` is present, it must be an RFC7517 JWK map. `publicKeyMultibase` must be a Multibase string for every VM type (§5). A present but empty `publicKeyMultibase` or `secretKeyMultibase` is an error (§5).
3. `id` (URL), `type` and `controller` (URL) are required. `type` is a string that references exactly one VM type and is not limited to two types. `Multikey` and `JsonWebKey` get full validation. Other types get only the generic form checks (§5) and are not used to verify proofs unless a codec is registered (§2).
4. Multikey: `z` + base58btc, with the correct multicodec prefix and length. A secret key header where a public key is expected is an error.
5. Service: `type` and `serviceEndpoint` (strings must be valid URLs) are required. Duplicate `id` values are prohibited. In V10 validation, `id` is required (RFC 3986 URI) and endpoint strings are normalized RFC 3986 URIs (§8). Additional properties are kept in `Extra`.
6. Relationship values: a set of one or more VMs, embedded or referenced.
7. Retrieve VM (§3): implement the two-way binding and the 5 errors.
8. Fragment Resolution (§4): match id == fragment or id == base + fragment.
9. `expires` / `revoked`: XSD dateTimeStamp. Proofs are not verified after that time.
10. Consuming a non-conforming document MUST produce an error.

CID errors (with RFC9457, `type` is `https://w3id.org/security#<NAME>`): `INVALID_VERIFICATION_METHOD_URL`, `INVALID_CONTROLLED_IDENTIFIER_DOCUMENT`, `INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID`, `INVALID_VERIFICATION_METHOD`, `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`. When these errors are exposed through an HTTP interface, RFC9457 SHOULD be used (§3.5). If RFC9457 is used, `title` SHOULD be a short but specific human-readable string and `detail` SHOULD be a longer human-readable explanation.
