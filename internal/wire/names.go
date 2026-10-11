package wire

import "slices"

// Property names of the DID document data model (DID Core 1.0 §5, DID 1.1
// §5, CID 1.0 §2.1 to §2.3).
const (
	PropID                   = "id"
	PropController           = "controller"
	PropAlsoKnownAs          = "alsoKnownAs"
	PropVerificationMethod   = "verificationMethod"
	PropService              = "service"
	PropType                 = "type"
	PropServiceEndpoint      = "serviceEndpoint"
	PropExpires              = "expires"
	PropRevoked              = "revoked"
	PropPublicKeyMultibase   = "publicKeyMultibase"
	PropPublicKeyJwk         = "publicKeyJwk"
	PropSecretKeyMultibase   = "secretKeyMultibase"
	PropSecretKeyJwk         = "secretKeyJwk"
	PropAuthentication       = "authentication"
	PropAssertionMethod      = "assertionMethod"
	PropKeyAgreement         = "keyAgreement"
	PropCapabilityInvocation = "capabilityInvocation"
	PropCapabilityDelegation = "capabilityDelegation"
)

// DocumentProperties returns the core properties of a DID document in the
// order a producer writes them, in a fresh slice: id, controller,
// alsoKnownAs, verificationMethod, the five verification relationships in
// specification order, and service.
func DocumentProperties() []string {
	return []string{PropID, PropController, PropAlsoKnownAs, PropVerificationMethod,
		PropAuthentication, PropAssertionMethod, PropKeyAgreement, PropCapabilityInvocation,
		PropCapabilityDelegation, PropService}
}

// MethodProperties returns the properties of a verification method that the
// data model names, in the order a producer writes them, in a fresh slice.
func MethodProperties() []string {
	return []string{PropID, PropType, PropController, PropExpires, PropRevoked,
		PropPublicKeyMultibase, PropPublicKeyJwk, PropSecretKeyMultibase, PropSecretKeyJwk}
}

// ServiceProperties returns the properties of a service that the data model
// names, in the order a producer writes them, in a fresh slice.
func ServiceProperties() []string {
	return []string{PropID, PropType, PropServiceEndpoint}
}

// IsSecretProperty reports whether name holds secret key material, which a
// producer writes only on request (docs/00 FR-P3; CID 1.0 §2.2.2, §2.2.3).
func IsSecretProperty(name string) bool {
	return name == PropSecretKeyMultibase || name == PropSecretKeyJwk
}

// IsDocumentProperty reports whether name is a core property of a DID
// document.
func IsDocumentProperty(name string) bool {
	return slices.Contains(DocumentProperties(), name)
}
