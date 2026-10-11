#!/usr/bin/env python3
"""Build conformance/requirements.json from extracted statements and review decisions.

Inputs:
  STATEMENTS_DIR  {core10,did11,cid10,res10,didkey,didweb}.json from
                  extract_spec.py (didkey.json and didweb.json are extracted
                  with --respec)
  COVERAGE_JSON   one or more coverage verdict files ({"id","decision","reason"})
  LINKED_JSON     a JSON list of statement ids that the design restates (from compare.py)

The registry key of a statement names the exact publication (docs/14 §3), and
each entry records its scope, owners and a hash of its text, so a test that
names an id fails when the pinned text changes.

Usage: build_registry.py STATEMENTS_DIR LINKED_JSON COVERAGE_JSON... > requirements.json
"""

import hashlib
import json
import sys

KEYS = {
    "core10": "core10",
    "did11": "did11-cr20260305",
    "cid10": "cid10",
    "res10": "res10-crd20261001",
    "didkey": "didkey-2cc490c",
    "didweb": "didweb-ea423c1",
}

SPEC_AUTHOR = {"method-syntax", "method-operations", "security-requirements",
               "privacy-requirements", "extensibility", "method-architectures",
               "vdr-forks", "versioning", "vocabulary", "conformance"}

OWNERS = {
    "did-syntax": ["did"], "did-url-syntax": ["did"], "relative-did-urls": ["did"],
    "did-parameters": ["did", "dereferencer"],
    "data-model": ["document"], "core-properties": ["document"],
    "did-subject": ["document"], "subjects": ["document"],
    "did-controller": ["document"], "controllers": ["document"],
    "also-known-as": ["document"],
    "verification-methods": ["vm"], "verification-material": ["vm"],
    "Multikey": ["vm"], "JsonWebKey": ["vm"],
    "verification-relationships": ["document"], "authentication": ["document"],
    "assertion": ["document"], "key-agreement": ["document"],
    "capability-invocation": ["document"], "capability-delegation": ["document"],
    "services": ["vm"],
    "multibase-0": ["vm"], "multihash": ["vm"], "algorithms": ["vm"],
    "base-encode": ["vm"], "base-decode": ["vm"],
    "retrieve-verification-method": ["document"], "fragment-resolution": ["document"],
    "processing-errors": ["document"],
    "json-ld-context": ["producer", "consumer"], "context-injection": ["producer"],
    "production": ["producer"], "production-0": ["producer"],
    "consumption": ["consumer"], "consumption-0": ["consumer"],
    "json-ld-processors": ["producer", "consumer"],
    "remote-resource-integrity": ["consumer"], "media-types": ["producer"],
    "resolution": ["resolver"],
    "did-resolution": ["resolution/compat"],
    "did-resolution-options": ["resolution"],
    "did-resolution-metadata": ["resolution"],
    "did-document-metadata": ["document"],
    "did-url-dereferencing": ["resolution/compat"],
    "did-url-dereferencing-options": ["resolution"],
    "did-url-dereferencing-metadata": ["resolution"],
    "did-url-content-metadata": ["resolution"],
    "metadata-structure": ["resolution"],
    "datetime": ["document"],
    "resolving": ["resolver"], "resolving-algorithm": ["resolver"],
    "dereferencing": ["dereferencer"],
    "dereferencing-algorithm-resource": ["dereferencer"],
    "dereferencing-algorithm-fragment": ["dereferencer"],
    "resolver-architectures": ["resolution/universal"],
    "resolver-architectures-proxied": ["resolution/universal"],
    "errors": ["resolution"], "bindings-https": ["resolution/universal"],
    "caching": ["resolution/cache"],
    # did:key (didkey-2cc490c): the driver runs the algorithms; the JWK
    # encoding of a public key is a key codec.
    "document-creation-algorithm": ["method/key"],
    "signature-method-creation-algorithm": ["method/key"],
    "decode-public-key-algorithm": ["method/key"],
    "encode-jwk-algorithm": ["crypto"],
    "encryption-method-creation-algorithm": ["method/key"],
    "derive-encryption-key-algorithm": ["method/key"],
    "context-creation-algorithm": ["method/key"],
    # did:web (didweb-ea423c1): the driver checks the DID syntax the method
    # defines, turns a DID into its HTTPS URL, fetches it and checks the
    # document id. Building a DID from a URL (create-register) is offered by
    # the driver as a helper for controllers.
    "method-name": ["method/web"],
    "method-specific-identifier": ["method/web"],
    "create-register": ["method/web"],
    "read-resolve": ["method/web"],
}


# Statements whose section owner is not the package that carries the
# obligation. Each entry names the player or tool that performs it; the reason
# is recorded next to it.
STATEMENT_OWNERS = {
    # Accepting controller documents' methods needs resolution: relying party.
    "core10#did-controller.4": ["relyingparty"],
    # Dereferencing the canonical URL and comparing the returned id is resolve.
    "cid10#subjects.3": ["resolver"], "cid10#subjects.5": ["resolver"],
    # The second clause ("the identifier SHOULD be treated as invalid") binds
    # whoever receives the dereferenced document: the relying party checks
    # the returned id against the URL it dereferenced, as the resolver does.
    "cid10#subjects.4": ["resolver", "relyingparty"],
    # vm checks the dateTimeStamp format; not using a method after revoked
    # (MUST NOT) or expires (SHOULD cease) is enforced where a method is
    # chosen for a proof: relying party.
    "cid10#verification-methods.9": ["vm", "relyingparty"],
    "cid10#verification-methods.11": ["vm", "relyingparty"],
    # Who may update a document is enforced when updating: DID controller.
    "cid10#controllers.4": ["controller"],
    # Steps that dereference a URL and check the fetched document run in the
    # relying party; the pure selection steps stay with document.SelectMethod.
    "cid10#retrieve-verification-method.4": ["relyingparty"],
    "cid10#retrieve-verification-method.5": ["relyingparty"],
    # Fragment resolution walks every map of a fetched document: dereferencer.
    "cid10#fragment-resolution.1": ["dereferencer"],
    "cid10#fragment-resolution.2": ["dereferencer"],
    "cid10#fragment-resolution.3": ["dereferencer"],
    "cid10#fragment-resolution.4": ["dereferencer"],
    "cid10#fragment-resolution.5": ["dereferencer"],
    "cid10#fragment-resolution.6": ["dereferencer"],
    # Error objects and their type URLs are resolution types; HTTP is a binding.
    "cid10#processing-errors.1": ["resolution/universal"],
    "cid10#processing-errors.2": ["resolution"],
    "cid10#processing-errors.3": ["resolution"],
    "cid10#processing-errors.4": ["resolution"],
    # Producer and consumer obligations on serialized documents.
    "core10#services.6": ["producer"], "core10#services.7": ["consumer"],
    "cid10#JsonWebKey.12": ["producer"],
    # DID 1.1 §6.2.3 mixes producer and consumer sentences under one section.
    # Serializing with @context, its value, the undefined-term SHOULD NOT and
    # the media type are production rules; dropping undefined terms is a
    # consumption rule. Statement 1 (@context per JSON-LD 1.1) binds both.
    "did11#json-ld-processors.2": ["producer"],
    "did11#json-ld-processors.3": ["producer"],
    "did11#json-ld-processors.4": ["producer"],
    "did11#json-ld-processors.6": ["producer"],
    "did11#json-ld-processors.7": ["producer"],
    "did11#json-ld-processors.8": ["consumer"],
    # Treating a context as already retrieved with a pinned digest is done by
    # the jsonld tool, which embeds the contexts and checks their SHA-256 for
    # both players (docs/14 §2); neither player fetches or holds a context.
    "did11#remote-resource-integrity.1": ["jsonld"],
    "cid10#json-ld-context.1": ["jsonld"],
    # Key format conversion happens in the key codecs.
    "cid10#verification-material.2": ["crypto"],
    "cid10#verification-material.3": ["crypto"],
    # Using accept to pick a representation is the resolver's algorithm.
    "core10#did-resolution-options.2": ["resolver"],
    "core10#did-resolution-options.3": ["resolution/compat"],
    "res10#did-resolution-options.3": ["resolver"],
    # The caller that parses a returned didDocument with contentType is the
    # HTTPS binding client; in-process results carry a parsed document.
    "res10#did-resolution-metadata.4": ["resolution/universal"],
    # Dereferencing obligations of the DID URL dereferencer.
    "core10#did-url-dereferencing-options.3": ["dereferencer"],
    "res10#did-url-dereferencing-options.3": ["dereferencer"],
    "res10#did-url-dereferencing-options.5": ["dereferencer"],
    "res10#did-url-dereferencing-metadata.2": ["dereferencer"],
    "res10#did-url-dereferencing-metadata.4": ["dereferencer"],
    # Which metadata a driver includes is decided by the method driver.
    "core10#did-document-metadata.2": ["method/key", "method/web"],
    "core10#did-document-metadata.4": ["method/key", "method/web"],
    "core10#did-document-metadata.10": ["method/key", "method/web"],
    "res10#did-document-metadata.2": ["method/key", "method/web"],
    "res10#did-document-metadata.4": ["method/key", "method/web"],
    "res10#did-document-metadata.10": ["method/key", "method/web"],
    # The Ed25519 to X25519 conversion is key arithmetic: key codecs.
    "didkey#derive-encryption-key-algorithm.5": ["crypto"],
}

# Statements addressed to specification authors outside the sections listed
# in SPEC_AUTHOR (docs/14 §5).
SPEC_AUTHOR_IDS = {
    "cid10#Multikey.24",
    "res10#did-document-metadata.17", "res10#did-document-metadata.22",
    "res10#did-url-content-metadata.1",
}


# Statements extracted as algorithm steps that state no requirement, with the
# reason recorded in the registry.
OUT_OF_SCOPE_IDS = {
    "didkey#signature-method-creation-algorithm.5":
        "informative: explains how the previous sentence is usually met and states no requirement",
    "didweb#read-resolve.9":
        "deployment: DNS resolution is performed by the dialer of the *http.Client the caller "
        "injects; did-go ships no DNS-over-HTTPS resolver and documents that the caller "
        "configures one (method/web package documentation)",
}


def owners_for(spec, statement):
    section = statement["section"]
    override = STATEMENT_OWNERS.get(statement["id"])
    if override is not None:
        return override
    if spec == "core10" and section in {"did-resolution-metadata",
                                         "did-url-dereferencing-metadata"}:
        # The v1.0 metadata contract (string errors, resolveRepresentation)
        # lives in the v1.0 adapter.
        return ["resolution/compat"]
    if section == "production-and-consumption":
        text = statement["text"]
        if "conforming producer" in text or "The conforming producer" in text:
            return ["producer"]
        if "conforming consumer" in text:
            return ["consumer"]
        return []
    if spec == "res10" and section in {"did-resolution-options", "did-resolution-metadata",
                                        "did-url-dereferencing-options",
                                        "did-url-dereferencing-metadata"}:
        return ["resolution"]
    if spec == "core10" and section in {"did-resolution", "did-url-dereferencing"}:
        return ["resolution/compat"]
    return OWNERS.get(section, [])


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    statements_dir, linked_path = sys.argv[1], sys.argv[2]
    with open(linked_path, encoding="utf-8") as handle:
        linked = set(json.load(handle))
    decisions = {}
    for path in sys.argv[3:]:
        with open(path, encoding="utf-8") as handle:
            for item in json.load(handle):
                decisions[item["id"]] = item
    entries = []
    for short, key in KEYS.items():
        with open(f"{statements_dir}/{short}.json", encoding="utf-8") as handle:
            statements = json.load(handle)
        for s in statements:
            local = s["id"].split("#", 1)[1]
            owners = owners_for(short, s)
            decision = decisions.get(s["id"], {})
            if not s["normative"]:
                scope, reason = "out-of-scope", "informative"
            elif s["section"] in SPEC_AUTHOR or s["id"] in SPEC_AUTHOR_IDS:
                scope, reason = "out-of-scope", "spec-author"
            elif s["id"] in OUT_OF_SCOPE_IDS:
                scope, reason = "out-of-scope", OUT_OF_SCOPE_IDS[s["id"]]
            elif decision.get("decision") == "OUT_OF_SCOPE":
                scope, reason = "out-of-scope", decision.get("reason", "")
            elif not owners:
                scope, reason = "out-of-scope", "representation-author"
            elif s["id"] in linked or decision.get("decision") in {"COVERED", "GAP"}:
                scope, reason = "in-scope", ""
            else:
                scope, reason = "in-scope", "not linked by the design review; owner assigned by section"
            entries.append({
                "id": f"{key}#{local}",
                "spec": key,
                "section": s["section"],
                "term": s.get("term", ""),
                "text": s["text"],
                "textSHA256": hashlib.sha256(s["text"].encode("utf-8")).hexdigest(),
                "algorithmStep": s.get("algorithm_step", False),
                "parent": (f"{key}#{s['parent'].split('#', 1)[1]}" if s.get("parent") else None),
                "scope": scope,
                "reason": reason,
                "owners": owners if scope == "in-scope" else [],
            })
    json.dump({"generatedFrom": "tools/xbar/build_registry.py", "requirements": entries},
              sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
