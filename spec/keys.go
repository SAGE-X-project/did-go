package spec

// Key names an exact snapshot of a specification. Requirement ids are written
// as Key + "#" + section + "." + ordinal (docs/14 §3, §7.1).
type Key string

// Specification keys.
const (
	// KeyCore10 is DID Core 1.0, W3C Recommendation 2022-07-19.
	KeyCore10 Key = "core10"
	// KeyDID11 is DID 1.1, W3C Candidate Recommendation Snapshot 2026-03-05.
	KeyDID11 Key = "did11-cr20260305"
	// KeyCID10 is Controlled Identifiers 1.0, W3C Recommendation 2025-05-15.
	KeyCID10 Key = "cid10"
	// KeyRes10 is DID Resolution v1.0, W3C Candidate Recommendation Draft
	// 2026-10-01.
	KeyRes10 Key = "res10-crd20261001"
	// KeyDIDKey is the did:key method specification at commit 2cc490c.
	KeyDIDKey Key = "didkey-2cc490c"
	// KeyDIDWeb is the did:web method specification at commit ea423c1.
	KeyDIDWeb Key = "didweb-ea423c1"
)

// Keys returns every specification key, in a fresh slice.
func Keys() []Key {
	return []Key{KeyCore10, KeyDID11, KeyCID10, KeyRes10, KeyDIDKey, KeyDIDWeb}
}

// ConformanceProfile returns the tuple of specification keys conformance to
// version v is measured against, in a fresh slice. DID Core 1.0 contains its
// own resolution contract; DID 1.1 delegates to CID 1.0 and DID Resolution.
func ConformanceProfile(v Version) []Key {
	switch v {
	case V10:
		return []Key{KeyCore10}
	case V11:
		return []Key{KeyDID11, KeyCID10, KeyRes10}
	}
	return nil
}
