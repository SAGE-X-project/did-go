package key

import (
	"slices"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/internal/multiformats"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Multicodec values of the key length table of the Signature Method
// Creation Algorithm.
const (
	codecSecp256k1 uint64 = 0xe7
	codecX25519    uint64 = 0xec
	codecEd25519   uint64 = 0xed
	codecP256      uint64 = 0x1200
	codecP384      uint64 = 0x1201
)

// keyLength returns the public key byte length the did:key specification
// lists for a multicodec value.
func keyLength(codec uint64) (int, bool) {
	switch codec {
	case codecSecp256k1, codecP256:
		return 33, true
	case codecX25519, codecEd25519:
		return 32, true
	case codecP384:
		return 49, true
	}
	return 0, false
}

// keyType returns the crypto key type of a multicodec value, or false when
// the key type is not implemented (secp256k1).
func keyType(codec uint64) (crypto.KeyType, bool) {
	switch codec {
	case codecX25519:
		return crypto.X25519, true
	case codecEd25519:
		return crypto.Ed25519, true
	case codecP256:
		return crypto.P256, true
	case codecP384:
		return crypto.P384, true
	}
	return "", false
}

// contextFor is the table of the Context Creation Algorithm: the context
// URL a verification method type adds.
func contextFor(typ string) (string, bool) {
	switch typ {
	case "Ed25519VerificationKey2020", "X25519KeyAgreementKey2020", FormatJsonWebKey, FormatMultikey:
		return spec.ContextURLV11, true
	}
	return "", false
}

// identifier is a did:key identifier split by the Document Creation
// Algorithm.
type identifier struct {
	id             did.DID
	text           string
	multibaseValue string
}

// parseIdentifier runs steps 2, 3 and 5 of the Document Creation Algorithm.
func parseIdentifier(text string) (identifier, error) {
	parts := strings.Split(text, ":")
	var scheme, methodName, version, mbv string
	switch len(parts) {
	case 3:
		scheme, methodName, version, mbv = parts[0], parts[1], "1", parts[2]
	case 4:
		scheme, methodName, version, mbv = parts[0], parts[1], parts[2], parts[3]
	default:
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.4",
			"%q does not have three or four colon-separated components", text)
	}
	switch {
	case scheme != "did":
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.7", "scheme %q is not did", scheme)
	case methodName != "key":
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.8", "method %q is not key", methodName)
	case !positiveInteger(version):
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.9", "version %q is not a positive integer", version)
	case !strings.HasPrefix(mbv, "z"):
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.10", "multibase value %q does not begin with z", mbv)
	}
	id, err := did.Parse(text)
	if err != nil {
		return identifier{}, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.14", "%v", err)
	}
	return identifier{id: id, text: text, multibaseValue: mbv}, nil
}

// positiveInteger reports whether s is a decimal integer greater than zero.
func positiveInteger(s string) bool {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0
}

// decodePublicKey is the Decode Public Key Algorithm: base-58-btc decoding,
// then varint decoding of the multicodec header.
func decodePublicKey(mbv string) (uint64, []byte, error) {
	header, data, err := multiformats.DecodeMultibase(mbv)
	if err != nil || header != multiformats.HeaderBase58BTC {
		return 0, nil, raise(CodeInvalidDid, "didkey-2cc490c#decode-public-key-algorithm.2", "multibase value is not base-58-btc: %v", err)
	}
	codec, n, err := multiformats.ReadVarint(data)
	if err != nil {
		return 0, nil, raise(CodeInvalidDid, "didkey-2cc490c#decode-public-key-algorithm.3", "multicodec header: %v", err)
	}
	return codec, data[n:], nil
}

// publicKey runs the length and validity steps of the method creation
// algorithms for a decoded key.
func publicKey(codec uint64, raw []byte, lengthStatement string) (crypto.PublicKey, error) {
	want, ok := keyLength(codec)
	if !ok {
		return crypto.PublicKey{}, raise(CodeUnsupportedPublicKeyType, lengthStatement,
			"multicodec 0x%x is not a public key type known to this implementation", codec)
	}
	if len(raw) != want {
		return crypto.PublicKey{}, raise(CodeInvalidPublicKeyLength, lengthStatement,
			"multicodec 0x%x key is %d bytes, want %d", codec, len(raw), want)
	}
	t, ok := keyType(codec)
	if !ok {
		return crypto.PublicKey{}, raise(CodeUnsupportedPublicKeyType, "didkey-2cc490c#signature-method-creation-algorithm.4",
			"multicodec 0x%x keys are not supported by this implementation", codec)
	}
	k, err := crypto.NewPublicKey(t, raw)
	if err != nil {
		return crypto.PublicKey{}, raise(CodeInvalidPublicKey, "didkey-2cc490c#signature-method-creation-algorithm.6", "%v", err)
	}
	return k, nil
}

// methodRole holds the statement ids and allowed formats that differ
// between the signature and the encryption method creation algorithms.
type methodRole struct {
	idStatement, unknownStatement, experimentalStatement, controllerStatement string
	stableFormats                                                             []string
}

func signatureRole() methodRole {
	return methodRole{
		idStatement:           "didkey-2cc490c#signature-method-creation-algorithm.8",
		unknownStatement:      "didkey-2cc490c#signature-method-creation-algorithm.10",
		experimentalStatement: "didkey-2cc490c#signature-method-creation-algorithm.11",
		controllerStatement:   "didkey-2cc490c#signature-method-creation-algorithm.14",
		stableFormats:         []string{FormatMultikey, FormatJsonWebKey, "Ed25519VerificationKey2020"},
	}
}

func encryptionRole() methodRole {
	return methodRole{
		idStatement:           "didkey-2cc490c#encryption-method-creation-algorithm.6",
		unknownStatement:      "didkey-2cc490c#encryption-method-creation-algorithm.8",
		experimentalStatement: "didkey-2cc490c#encryption-method-creation-algorithm.9",
		controllerStatement:   "didkey-2cc490c#encryption-method-creation-algorithm.12",
		stableFormats:         []string{FormatMultikey, FormatJsonWebKey, "X25519KeyAgreementKey2020"},
	}
}

// buildMethod runs the steps the two method creation algorithms share
// after the key is known: id, format checks, type, controller and key
// material.
func (c config) buildMethod(ident identifier, mbv string, k crypto.PublicKey, role methodRole) (vm.Method, error) {
	id, err := methodID(ident.text, mbv, role.idStatement)
	if err != nil {
		return vm.Method{}, err
	}
	format := c.format
	if !slices.Contains(knownFormats(), format) {
		return vm.Method{}, raise(CodeUnsupportedPublicKeyType, role.unknownStatement, "public key format %q is not known to this implementation", format)
	}
	if !c.experimental && !slices.Contains(role.stableFormats, format) {
		return vm.Method{}, raise(CodeInvalidPublicKeyType, role.experimentalStatement,
			"public key format %q is experimental and experimental public key types are disabled", format)
	}
	controller, err := did.Parse(ident.text)
	if err != nil {
		return vm.Method{}, raise(CodeInvalidDid, role.controllerStatement, "%v", err)
	}
	m := vm.Method{ID: id, Type: format, Controller: controller}
	if format == FormatMultikey {
		m.PublicKeyMultibase = mbv
	} else {
		m.PublicKeyJwk = k.JWK()
	}
	return m, nil
}

// methodID concatenates the identifier, "#" and the multibase value.
func methodID(identifierText, mbv, statement string) (did.DIDURL, error) {
	u, err := did.ParseURL(identifierText + "#" + mbv)
	if err != nil {
		return did.DIDURL{}, raise(CodeInvalidDidURL, statement, "%v", err)
	}
	return u, nil
}

// signatureMethod is the Signature Method Creation Algorithm.
func (c config) signatureMethod(ident identifier) (vm.Method, error) {
	codec, raw, err := decodePublicKey(ident.multibaseValue)
	if err != nil {
		return vm.Method{}, err
	}
	k, err := publicKey(codec, raw, "didkey-2cc490c#signature-method-creation-algorithm.3")
	if err != nil {
		return vm.Method{}, err
	}
	return c.buildMethod(ident, ident.multibaseValue, k, signatureRole())
}

// encryptionMethod is the Encryption Method Creation Algorithm with the
// Derive Encryption Key Algorithm. The derivation is defined for Ed25519
// keys only; for any other key it returns false and no method.
func (c config) encryptionMethod(ident identifier) (vm.Method, bool, error) {
	codec, raw, err := decodePublicKey(ident.multibaseValue)
	if err != nil {
		return vm.Method{}, false, err
	}
	if codec != codecEd25519 {
		return vm.Method{}, false, nil
	}
	ed, err := publicKey(codec, raw, "didkey-2cc490c#signature-method-creation-algorithm.3")
	if err != nil {
		return vm.Method{}, false, err
	}
	x, err := crypto.DeriveX25519(ed)
	if err != nil {
		return vm.Method{}, false, raise(CodeInvalidPublicKey, "didkey-2cc490c#derive-encryption-key-algorithm.5", "%v", err)
	}
	k, err := publicKey(codecX25519, x.Raw(), "didkey-2cc490c#encryption-method-creation-algorithm.3")
	if err != nil {
		return vm.Method{}, false, err
	}
	mbv, err := k.Multikey()
	if err != nil {
		return vm.Method{}, false, raise(CodeInvalidPublicKey, "didkey-2cc490c#encryption-method-creation-algorithm.4", "%v", err)
	}
	m, err := c.buildMethod(ident, mbv, k, encryptionRole())
	return m, err == nil, err
}

// contextArray is the Context Creation Algorithm with defaultContext set to
// the base context of the target version.
func contextArray(v spec.Version, methods []vm.Method) document.List {
	profile, err := spec.ProfileOf(v)
	if err != nil {
		profile, _ = spec.ProfileOf(spec.Latest)
	}
	urls := []string{profile.ContextURL}
	for _, m := range methods {
		if u, ok := contextFor(m.Type); ok && !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	items := make([]document.Value, len(urls))
	for i, u := range urls {
		items[i] = document.String(u)
	}
	list, _ := document.NewList(items...)
	return list
}

// expand is the Document Creation Algorithm.
func (c config) expand(text string, opts representation.ProduceOptions) (*document.Document, error) {
	ident, err := parseIdentifier(text)
	if err != nil {
		return nil, err
	}
	sig, err := c.signatureMethod(ident)
	if err != nil {
		return nil, err
	}
	b := document.NewBuilder(ident.id).VerificationMethod(sig)
	for _, p := range []vm.Purpose{vm.Authentication, vm.AssertionMethod, vm.CapabilityInvocation, vm.CapabilityDelegation} {
		b.Relationship(p, vm.Ref(sig.ID))
	}
	methods := []vm.Method{sig}
	if c.deriveEncryption {
		enc, ok, err := c.encryptionMethod(ident)
		if err != nil {
			return nil, err
		}
		if ok {
			b.VerificationMethod(enc).Relationship(vm.KeyAgreement, vm.Ref(enc.ID))
			methods = append(methods, enc)
		}
	}
	if opts.JSONLD {
		b.RepresentationEntry("@context", contextArray(opts.Version, methods))
	}
	doc, err := b.Build()
	if err != nil {
		return nil, raise(CodeInvalidDid, "didkey-2cc490c#document-creation-algorithm.22", "the expanded document is not valid: %v", err)
	}
	return doc, nil
}
