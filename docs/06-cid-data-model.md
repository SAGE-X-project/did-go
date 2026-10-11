# CID 1.0: Data Model Rules and Go Mapping

> Source: `cid/index.html` (W3C Controlled Identifiers v1.0, [w3c/cid](https://github.com/w3c/cid) @ `2b962ac29e13`; line numbers in this document refer to that commit). See [standards.md](standards.md). Context `https://www.w3.org/ns/cid/v1`, vocabulary namespace `https://w3id.org/security#`.
> Role: DID Core v1.1 delegates the VM, Service and Relationship data models to this specification. This document fixes the **exact rules** that the `vm` and `crypto` packages in `05-go-design.md` must implement.
> Boundary: `equivalentId` and `canonicalId` belong to **DID Core (didDocumentMetadata)**, not to CID. See `07-did-resolution-contract.md`. CID defines only `id` (the base identifier) and the `canonical URL`.

---

## 1. Controlled Identifier Document core model (§2.1)

| Property | Required | Type / cardinality | Rule |
|----------|----------|--------------------|------|
| `id` | **yes** | URL string | MUST be present in the top-level map (§2.1.1 line 785). On dereference, the document is authoritative only if the canonical URL equals the base identifier. On mismatch, the document SHOULD be **treated as invalid** (line 808-812). |
| `controller` | no | string or set of strings (each a URL) | Each entry must identify an entity that can update the canonical document (line 894). If absent, the storage location determines control (line 901). |
| `alsoKnownAs` | no | set of URIs (RFC3986) | Equivalence may be inferred only when the relationship is **reciprocal**. |
| `service` | no | set of service maps | §7 |
| `verificationMethod` | no | set of VM maps | §2 |
| `authentication` / `assertionMethod` / `keyAgreement` / `capabilityInvocation` / `capabilityDelegation` | no | set of (URL string or VM map) | §6 |

**Conformance (§conformance):** "Conforming processors **MUST produce errors when non-conforming documents are consumed**" (line 461). This is a hard requirement on consumers.

---

## 2. Verification Method (§2.2)

A VM map **MUST contain** `id`, `type`, `controller`, plus the verification material that `type` defines (line 1147). Additional properties are allowed.

| Property | Required | Type / constraint |
|----------|----------|-------------------|
| `id` | **yes** | URL string. The verification method identifier. |
| `type` | **yes** | String that references exactly one VM type. Defined types: `Multikey`, `JsonWebKey`. |
| `controller` | **yes** | URL string. **Not necessarily the same as the document's controller.** It is only a *claim* and can be false (line 1245). Binding is established only by the algorithm in §3. |
| `expires` | no | XSD `dateTimeStamp` string. |
| `revoked` | no | XSD `dateTimeStamp` string. |
| Verification material | conditional | `publicKeyJwk` / `publicKeyMultibase` / `secretKeyJwk` / `secretKeyMultibase` (chosen by type). |

### 2.1 Verification material is mutually exclusive (§2.2.1, line 1306). Core rule.
> **"A verification method MUST NOT contain multiple verification material properties for the same material. ... expressing key material ... using both `publicKeyJwk` and `publicKeyMultibase` at the same time is prohibited."**

Key conversion is allowed, but it **must not change the external representation** (line 1313).

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
4. Recursively scan every map in document; stop at the first map whose
   id == fullyQualifiedFragment or id == fragmentIdentifier
5. return documentFragment  (null if none)
```
Duplicate fragments with the same id lead to undefined behavior (avoid them). Fragment rules for `application/did` documents may differ (JSON-LD rules).

---

## 5. Multikey (§2.2.2): Go `crypto` mapping

`type == "Multikey"`. `publicKeyMultibase` / `secretKeyMultibase` are Multibase (**base58-btc, header `z`**) = `z` + base58btc(multicodec varint prefix ‖ raw key bytes).

**Public key multicodec prefixes (each row is a MUST):**

| Key type | 2-byte prefix | Raw bytes | Total length |
|----------|---------------|-----------|--------------|
| Ed25519 | `0xed01` | 32 | 34 |
| ECDSA P-256 | `0x8024` | 33 (compressed) | 35 |
| ECDSA P-384 | `0x8124` | 49 (compressed) | 51 |
| BLS12-381 G2 | `0xeb01` | 96 | 98 |
| SM2 | `0x8624` | 33 | 35 |

**Secret key prefixes:** Ed25519 `0x8026` (34), P-256 `0x8626` (34), P-384 `0x8726` (50), BLS12-381 G2 `0x8030` (98), SM2 `0x9026` (34).

- An unknown header, or a value that is not a public key header where a public key is expected, **raises an error** (line 1528).
- **Alternative encodings MUST NOT be defined** for key types that are already defined (line 1537).

## 6. JsonWebKey (§2.2.3)

`type == "JsonWebKey"`.
- `publicKeyJwk`: an RFC7517 JWK map. It **MUST NOT contain private or secret members such as `d`** (line 1569, 1633).
- `kid`: if present, it SHOULD equal `id` or a part of it (path, query or fragment). Using `kid` as the VM fragment is RECOMMENDED. A JWK Thumbprint (RFC7638, SHA-256) as `kid` is RECOMMENDED.
- `alg`: SHOULD be included to prevent misuse across algorithms. `crv` is REQUIRED for EC keys.
- `secretKeyJwk`: **MUST NOT be used** in structures that may be made public.

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

## 8. Service (§2.1.4)

Each service map **MUST contain** `type` and `serviceEndpoint`. `id` is OPTIONAL in the sub-definition, but **services with the same `id` MUST NOT be duplicated** (line 1057).

| Sub-property | Required | Constraint |
|--------------|----------|------------|
| `id` | (conditional) | A URL if present. Must not be duplicated within the document. |
| `type` | **yes** | string or set of strings. |
| `serviceEndpoint` | **yes** | a single string, a single map, or a set of strings and maps. **Each string MUST be a valid URL** (line 1072). |

> Tension inside the specification: the parent sentence makes `id` required, while the sub-definition makes it optional. The validator follows the sub-definition (the more specific one) but raises a warning flag.

---

## 9. Multibase and Multihash data types (§2.4)

- **Multibase** (§`#multibase-0`): `z` means base58-btc, `u` means base64-url-no-pad. On encoding, the header character MUST be prepended. On decoding, everything after the first character is Base Decoded with the corresponding alphabet.
- **Multihash** (§`#multihash`): varint(header) ‖ varint(length) ‖ digest. For example `sha2-256` = `0x12` (32 bytes).
- `multibase` RDF data type URL: `https://w3id.org/security#multibase`.

## 10. Context and media type

- JSON-LD Context URL: `https://www.w3.org/ns/cid/v1` (pinned by SHA-256). During JSON-LD processing it MUST be treated as already resolved (line 2866).
- **Context Injection** (line 2917): if `@context` is missing or a term is unmapped, `https://www.w3.org/ns/cid/v1` (or the DID v1.1 context) MUST be injected or added.
- Not using JSON-LD is allowed (MAY). The meaning is the same.
- Media type **`application/cid`** (§IANA): follows the `application/json` encoding rules.

---

## 11. Go mapping summary (generic CID layer; relationship to `05-go-design.md` §3.3)

> This mapping is a reference shape from the viewpoint of **generic CID documents** (which allow non-DID controllers). **The canonical form for the DID document implementation is the type-enforced form in `05` §3.3** (`ID did.DIDURL` / `Controller did.DID`). The string form below is the mapping to use when the CID layer is reused independently of DIDs.

```go
// vm.Method (CID §2.2): id and controller are string URLs (a referenced VM may live in another document, so did.DID is not enforced here; the DID Core layer adds that constraint)
type Method struct {
    ID         string     // URL (constrained to a DID URL by DID Core)
    Type       string     // "Multikey" | "JsonWebKey"
    Controller string     // URL (constrained to a DID by DID Core). Only a claim; binding comes from the Retrieve algorithm
    Expires    *time.Time // XSD dateTimeStamp
    Revoked    *time.Time
    // Verification material: exactly one (§2.2.1)
    PublicKeyMultibase string
    PublicKeyJwk       map[string]any
    // Secret material: excluded from serialization by default
    SecretKeyMultibase string
    SecretKeyJwk       map[string]any
}

// crypto.Multikey: multicodec prefix table (§5)
type MultikeyCodec struct {
    Prefix    []byte // e.g. {0xed,0x01} Ed25519
    RawLen    int    // 32
    Algorithm string // "Ed25519"
}
```

**Hard validator rules (to be turned into tests):**
1. `publicKeyJwk` XOR `publicKeyMultibase` (both at once is prohibited). No material may be duplicated.
2. `publicKeyJwk` must not contain private members such as `d`.
3. `id` (URL), `type` (`Multikey` or `JsonWebKey`) and `controller` (URL) are required.
4. Multikey: `z` + base58btc, with the correct multicodec prefix and length. A secret key header where a public key is expected is an error.
5. Service: `type` and `serviceEndpoint` (strings must be valid URLs) are required. Duplicate `id` values are prohibited.
6. Relationship values: a set of one or more VMs, embedded or referenced.
7. Retrieve VM (§3): implement the two-way binding and the 5 errors.
8. Fragment Resolution (§4): match id == fragment or id == base + fragment.
9. `expires` / `revoked`: XSD dateTimeStamp. Proofs are not verified after that time.
10. Consuming a non-conforming document MUST produce an error.

CID errors (with RFC9457, `type` is `https://w3id.org/security#<NAME>`): `INVALID_VERIFICATION_METHOD_URL`, `INVALID_CONTROLLED_IDENTIFIER_DOCUMENT`, `INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID`, `INVALID_VERIFICATION_METHOD`, `INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD`.
