# DID Core v1.0/v1.1: State Diagrams

> Defines the DID lifecycle (§Method Operations) and the library's internal processing states (parsing, representation, resolution) as state machines.

---

## 1. DID Lifecycle (Create → Update → Deactivate)

Corresponds to the method CRUD operations (§Method Operations).

```mermaid
stateDiagram-v2
    [*] --> NonExistent
    NonExistent --> Active: Create (authz passed, recorded in VDR)
    NonExistent --> [*]: Create failed (Unauthorized / conflict)

    Active --> Active: Update (authz passed, new versionId)
    Active --> Deactivated: Deactivate (authz passed)
    Active --> Active: Resolve (Read, no side effects)

    Deactivated --> Deactivated: Resolve → metadata{deactivated:true}
    Deactivated --> [*]

    note right of Active
        Resolve always returns a conforming document.
        Update only if the method supports it; otherwise state is unchanged.
    end note
    note right of Deactivated
        Deactivation is irreversible (subject to method policy).
        A Resolve result has didDocument=null, didDocumentMetadata.deactivated=true,
        and HTTP 410 (DID Resolution §4.4; the 410 comes from the §12.1 HTTP(S) binding).
    end note
```

---

## 2. DID / DID URL Parsing States (UC-1)

```mermaid
stateDiagram-v2
    [*] --> Start
    Start --> SchemeChecked: "did:" confirmed
    Start --> Invalid: scheme mismatch
    SchemeChecked --> MethodParsed: method-name (lowercase + digit)
    SchemeChecked --> Invalid: invalid method-char
    MethodParsed --> MSIDParsed: method-specific-id (idchar/pct)
    MethodParsed --> Invalid: invalid idchar
    MSIDParsed --> DIDValid: end of input
    MSIDParsed --> URLParsing: path/query/fragment present

    URLParsing --> PathParsed: path-abempty (RFC3986)
    PathParsed --> QueryParsed: "?" query
    PathParsed --> FragmentParsed: "#" fragment
    QueryParsed --> FragmentParsed: "#" fragment
    URLParsing --> Invalid: RFC3986 violation
    PathParsed --> URLValid: end
    QueryParsed --> URLValid: end
    FragmentParsed --> URLValid: end

    DIDValid --> [*]
    URLValid --> [*]
    Invalid --> [*]: ErrInvalidSyntax(pos)
```

---

## 3. Representation Processing States (Produce / Consume)

```mermaid
stateDiagram-v2
    direction LR
    state "Produce (UC-3)" as P {
        [*] --> P_Assert
        P_Assert --> P_Reject: non-conforming document (for a V10 target document.Validate(d, spec.V10) requires service.id)
        P_Assert --> P_Strip: conforming
        P_Strip --> P_Context: secretKey* removed
        P_Context --> P_Encode: if JSON-LD, inject version-specific @context (v1 / v1.1)
        P_Encode --> P_Done: bytes + version-specific media type
        P_Reject --> [*]: error
        P_Done --> [*]
    }
    state "Consume (UC-4)" as C {
        [*] --> C_TypeCheck
        C_TypeCheck --> C_RootCheck: representation selected from the declared media type (09 §4)
        C_RootCheck --> C_Error: root ≠ JSON Object
        C_RootCheck --> C_VerDetect: JSON Object
        C_VerDetect --> C_Map: version fixed (the DID media type decides, a non-v1 @context on did+json is recorded in UnexpectedContext, low-precision uses @context[0], else Expected, else VUnknown, 09 §4 steps 1 to 5)
        C_VerDetect --> C_Error: @context that does not fit did+ld+json or did, or a Strict violation
        C_Map --> C_Preserve: type mapping
        C_Preserve --> C_LD: rule 3 known repr-specific→map / rule 4 unrecognized→data model
        C_LD --> C_Validate: undefined term drop (JSON-LD)
        C_Validate --> C_Error: non-conforming
        C_Validate --> C_Done: Document
        C_Error --> [*]: error
        C_Done --> [*]
    }
```

---

## 4. Resolve Processing States (UC-5)

```mermaid
stateDiagram-v2
    [*] --> Parsing
    Parsing --> ErrInvalidDid: syntax violation
    Parsing --> MethodLookup: parse succeeded
    MethodLookup --> ErrMethodNotSupported: method not registered
    MethodLookup --> OptionCheck: Method lookup succeeded
    OptionCheck --> ErrFeatureNotSupported: option not supported
    OptionCheck --> ErrInvalidOptions: option invalid
    OptionCheck --> Reading: options validated
    Reading --> ErrNotFound: not in VDR
    Reading --> ErrFeatureNotSupported: driver does not support an option (ErrNotSupported, for example versionTime)
    Reading --> ErrInvalidDoc: driver obtained an invalid document (ErrInvalidDocument)
    Reading --> ErrInvalidDid: the DID does not conform to its method (ErrInvalidInput)
    Reading --> ErrInternal: other driver error
    ErrInternal --> [*]: error.type=…#INTERNAL_ERROR (500)
    Reading --> ErrInvalidDoc: driver metadata violation (checked before deactivated, 12 §6.2)
    Reading --> Deactivated: deactivated record
    Reading --> Consuming: raw document obtained
    Consuming --> ErrInvalidDoc: consumption failed
    Consuming --> Resolved: Document created
    Consuming --> ErrFeatureNotSupported: no acceptable representation can be produced (resolution.NewAcceptNotSupported, 12 §6.2 step 4)

    Resolved --> [*]: doc + meta{contentType = media type of the bytes returned in Raw (12 §6.2)}
    Deactivated --> [*]: didDocument=null + docMeta{deactivated:true} (HTTP 410, not an error)
    ErrInvalidDid --> [*]: error.type=…#INVALID_DID (400)
    ErrMethodNotSupported --> [*]: error.type=…#METHOD_NOT_SUPPORTED (501)
    ErrFeatureNotSupported --> [*]: error.type=…#FEATURE_NOT_SUPPORTED (501)
    ErrInvalidOptions --> [*]: error.type=…#INVALID_OPTIONS (400)
    ErrNotFound --> [*]: error.type=…#NOT_FOUND (404)
    ErrInvalidDoc --> [*]: error.type=…#INVALID_DID_DOCUMENT (500)

    note right of Deactivated
        deactivated is not an error;
        it is signaled by didDocumentMetadata.deactivated=true (07 §1.1)
    end note
```

---

## 5. Verification Method Reference Resolution States (UC-10)

```mermaid
stateDiagram-v2
    [*] --> Inspect
    Inspect --> Embedded: element is a map
    Inspect --> Referenced: element is a string (DID URL)
    Embedded --> Ready: use inline VM
    Referenced --> Absolutize: if relative DID URL, make absolute (RFC3986 §5)
    Absolutize --> Lookup: match id in verificationMethod
    Lookup --> Dangling: no match
    Lookup --> Ready: VM found
    Ready --> KeyParse: public key material (publicKeyMultibase or publicKeyJwk, at most one)
    Ready --> NoKey: no public key material (conforming, but cannot verify proofs)
    KeyParse --> [*]: used for verification
    NoKey --> [*]: not used for proof verification
    Dangling --> [*]: document.ConformanceError (INVALID_VERIFICATION_METHOD)
```

---

## 6. State Machine to Spec Basis Mapping

| State machine | Spec basis | FR |
|---------------|------------|-----|
| §1 Lifecycle | §Method Operations (Create/Read/Update/Deactivate) | FR-M1 to M4 |
| §2 Parsing | §DID Syntax / §DID URL Syntax ABNF | FR-S1 to S3 |
| §3 Representation | §Production and Consumption, §JSON, §JSON-LD; version detection and profiles from v1.0 REC §5.4/§6 plus `09` §4 and §5 | FR-R1 to R4, FR-V1 to V3 |
| §4 Resolve | DID-Resolution resolve algorithm, RFC9457 errors (07 §1.1, §4) | FR-X1,X4 |
| §5 VM reference | §Verification Relationships, §Relative DID URLs, CID Retrieve VM (06 §3) | FR-D4,S3 |
