# DID Core v1.0/v1.1: Component Diagram

> The spec's delegation boundaries (A: Resolution, B: CID, C: single media type) are reflected directly as component boundaries. The core has no dependencies, and external delegation is isolated behind interfaces. **v1.0 support (D)** does not split the core in two; it appears only as representation parameters, validation profiles and the `resolution/compat` adapter ([`09`](09-v1.0-compat.md)).

---

## 1. Overall Component Structure

All components below belong to the root module `github.com/sage-x-project/did-go` (standard core). The SAGE extension lives outside it, in the separate `advanced/sage` module with its own `go.mod` ([`12`](12-standard-core-and-sage-extension.md) §3). No package in the root module imports it.

```mermaid
flowchart TB
    subgraph app["Application layer"]
        APP[Application / Verifier / Controller]
    end

    subgraph core["DID Core (no dependencies, standard library only)"]
        SPEC["spec<br/>(SpecVersion V10/V11)"]
        SYN["did<br/>(DID / DID URL parsing and validation)"]
        MODEL["document<br/>(data model, Builder, Validator, Profile)"]
        VM["vm<br/>(VerificationMethod, Relationship, Service)"]
        REPR["representation<br/>(Producer / Consumer, version detection and parameterization)"]
        LD["jsonld<br/>(@context handling, term filter, dual v1 and v1.1)"]
    end

    subgraph contract["Delegated contract layer (interfaces)"]
        RES["resolution<br/>(Resolver and Dereferencer interfaces, metadata, error codes)"]
        METH["method<br/>(Method interface, Registry)"]
    end

    subgraph adapters["Adapters / plugins (replaceable)"]
        MKEY["method/key<br/>(did:key reference implementation)"]
        MWEB["method/web<br/>(did:web reference implementation)"]
        RESOLVER["resolution/universal<br/>(DID-RESOLUTION conformant adapter)"]
        COMPAT["resolution/compat<br/>(v1.0 contract adapter:<br/>resolveRepresentation, string errors)"]
        CRYPTO["crypto<br/>(Multikey/JWK codecs, signature verification)"]
    end

    subgraph advmod["Separate module: advanced/sage (own go.mod, opt-in, see 12 §3)"]
        ADV["advanced/sage<br/>(did:sage method driver, SAGE projection,<br/>SAGE consumption profile, error mapping)"]
    end

    subgraph ext["External systems"]
        VDR[("Verifiable Data Registry<br/>(ledger / DNS / DB)")]
        CTX[["base contexts<br/>…/ns/did/v1 + …/ns/did/v1.1<br/>(embedded, SHA-256 pinned)"]]
    end

    APP --> SYN & MODEL & REPR & RES
    REPR --> SPEC
    MODEL --> VM
    MODEL --> SYN
    REPR --> MODEL
    REPR --> LD
    LD -. integrity check .-> CTX
    RES --> METH
    RES --> REPR
    METH --> MKEY & MWEB
    MKEY & MWEB --> CRYPTO
    MKEY & MWEB --> VDR
    RESOLVER --> RES
    COMPAT --> RES
    COMPAT --> REPR
    VM --> CRYPTO
    ADV -. implements method driver .-> METH
```

---

## 2. Component Responsibilities

| Component | Responsibility | FR | Depends on |
|-----------|----------------|----|------------|
| `spec` | SpecVersion (V10/V11/VUnknown), version-specific context URLs | FR-V1 | none |
| `did` | DID/DID URL ABNF parsing and validation, relative URL absolutization, percent-encoding (version independent) | FR-S1 to S6 | none |
| `document` | DID document data model (INFRA types, v1.1 superset), Builder, Validator (+ProfileV10), immutable documents, relationship/reference selectors | FR-D1,D2,D7,V3 | `did`, `vm` |
| `vm` | VerificationMethod/Service/5 Relationship structs, CID constraint validation (key XOR, etc.) | FR-D3,D4,D5,P3 | `did`, `crypto` |
| `representation` | JSON Producer/Consumer (`application/did` plus 2 legacy types), version detection and SpecVersion production, deterministic lossless serialization | FR-R1,R2,R4,R5,V1,V2,V3 | `document`, `jsonld`, `spec` |
| `jsonld` | `@context` injection and validation (per version), undefined term drop, base context integrity (dual v1 and v1.1) | FR-R3,R6,V5 | embedded contexts |
| `resolution` | Resolver/Dereferencer interfaces, resolutionOptions/metadata (including equivalentId/canonicalId)/error catalog | FR-X1 to X4,D6 | `method`, `representation` |
| `method` | Method interface (CRUD + authz), method-name Registry | FR-M1 to M6 | `did`, `document` |
| `method/key`,`method/web` | Reference method implementations | FR-M1 to M6 | `method`, `crypto`, VDR |
| `crypto` | Multikey/JWK encoding and signature verification (CID delegation) | FR-D3,P1 | external crypto library |
| `resolution/universal` | DID-RESOLUTION spec conformant adapter | FR-X1 to X4 | `resolution` |
| `resolution/compat` | v1.0 REC §7 contract adapter: `resolveRepresentation()`, RFC9457 to string error mapping, accepts `hl` | FR-V4 | `resolution`, `representation` |

---

## 3. Interface Boundaries (Ports & Adapters)

```mermaid
flowchart LR
    subgraph "Core (stable API)"
        direction TB
        IResolver{{"Resolver interface"}}
        IDereferencer{{"Dereferencer interface"}}
        IMethod{{"Method interface"}}
        ICodec{{"KeyCodec interface"}}
    end

    UNIV[Universal Resolver adapter] -.implements.-> IResolver
    V10C[v1.0 compat adapter] -.wraps.-> IResolver
    DKEY[did:key] -.implements.-> IMethod
    DWEB[did:web] -.implements.-> IMethod
    ED25519[ed25519 codec] -.implements.-> ICodec
    P256[P-256 codec] -.implements.-> ICodec

    IResolver --> IMethod
    IDereferencer --> IResolver
    IMethod --> ICodec
```

**Design principles**
- **Hexagonal (Ports & Adapters):** the core exposes only interfaces (ports). Methods, crypto and resolvers are injected as adapters. This serves NFR-2 (extensibility) and NFR-3 (dependency-free core).
- **Isolation of delegation boundaries:** if DID-RESOLUTION or CID details change, the core data model stays unchanged. Only the `resolution`/`crypto` adapters are replaced.
- **One-way dependencies:** `adapters → contract → core`. The core does not know the adapters (inversion).

---

## 4. Deployment View

```mermaid
flowchart TB
    subgraph clientlib["Embedded library mode"]
        A1[Go application]
        A1 --> CORELIB[[did-core packages]]
        CORELIB --> ADPT1[method plugins]
    end

    subgraph service["Resolver service mode"]
        HTTP[HTTP API<br/>GET /1.0/identifiers/:did]
        HTTP --> RSVC[resolution.Resolver]
        RSVC --> REG[method.Registry]
        REG --> MDRV[registered methods]
        MDRV --> VDRS[("VDR: ledger/DNS/DB")]
    end
```

Both deployment forms reuse the same core. Service mode exposes the DID-RESOLUTION HTTP binding (`application/did` responses) through the `resolution/universal` adapter. **v1.0 clients** have no separate endpoint; they negotiate a V10 representation on the same binding through the Accept header (`application/did+ld+json`/`did+json`) (`09` §6.3).
