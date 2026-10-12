package sage

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"

	"github.com/sage-x-project/did-go/did"
)

// Source supplies authoritative observations of did:sage records. It is the
// trust decision of the deployment (chapter 10 RESOLVE-02): a configured
// SAGE core that acquires a fresh, authorized observation under chapter 09
// and validates the complete record, its proofs, version monotonicity and
// state before returning it. A peer-supplied resolver URL is never a Source.
//
// Observe performs a new observation on every call. It returns an *Error
// with a RESOLVE-05 code when the identifier is malformed or too large, the
// registry kind is not supported, the record does not exist or cannot be
// read, or the observation is stale or invalid. Any other error is treated
// as record.unreachable.
type Source interface {
	Observe(ctx context.Context, d did.DID) (Record, error)
}

// State is the lifecycle state of a record (chapter 09 §1).
type State string

// Record states.
const (
	StateCreated     State = "created"
	StateActive      State = "active"
	StateDeactivated State = "deactivated"
)

// KeyState is the state of a key entry (chapter 09 §1).
type KeyState string

// Key states.
const (
	KeyAccepted KeyState = "accepted"
	KeyRevoked  KeyState = "revoked"
)

// Algorithm names of chapter 11 TABLE-02 and TABLE-03.
const (
	AlgEd25519   = "ed25519"
	AlgP256      = "ecdsa-p256-sha256"
	AlgSecp256k1 = "sage-secp256k1-keccak256"
	AlgX25519    = "x25519"
)

// Record is one validated observation of a did:sage record: the chapter 09
// record members a projection needs and the RESOLVE-03 observation data.
// Proofs are not carried; the Source has verified them.
type Record struct {
	// DID is the canonical identifier (chapter 06).
	DID did.DID
	// Controller is the ASCII authorization identifier, 1 to 256 bytes.
	Controller string
	// State is created, active or deactivated.
	State State
	// Version is the decimal registry version without leading zero.
	Version string
	// Keys are 1 to 128 entries, including tombstones, sorted by name.
	Keys []Key
	// Services are 0 to 16 entries sorted by name.
	Services []Service
	// Observation describes the observation the record comes from.
	Observation Observation
}

// Key is a key entry. Material holds the chapter 11 raw bytes: 32 bytes for
// Ed25519 and X25519, the 65-byte uncompressed point for P-256 and
// secp256k1.
type Key struct {
	Name     string
	Alg      string
	Material []byte
	State    KeyState
	// Expires is the Unix second from which the key is unusable, or nil.
	Expires *int64
}

// Service is a registry service.
type Service struct {
	Name string
	Type string
	URI  string
}

// Observation is the RESOLVE-03 observation data. Exactly one of BlockHash
// (an eip155 registry: the finalized block hash) and Issued (a web
// registry: the issued integer) is set.
type Observation struct {
	BlockHash string
	Issued    *int64
	// Source is the configured source identity, ASCII, at most 2048 bytes.
	Source string
	// Time is the local Unix second when the observation completed. It is
	// the time against which key expiry is evaluated.
	Time int64
}

// Record bounds of chapter 09 §1 and chapter 10 RESOLVE-03.
const (
	maxKeys          = 128
	maxServices      = 16
	maxControllerLen = 256
	maxSourceLen     = 2048
	maxServiceType   = 64
	maxServiceURI    = 2048
	maxExpires       = 9007199254740991
)

// keyName is the chapter 06 key-id rule, which service names also use.
var keyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// usable reports whether k is accepted and unexpired at now (chapter 09 §1:
// unusable when now >= expires).
func (k Key) usable(now int64) bool {
	return k.State == KeyAccepted && (k.Expires == nil || now < *k.Expires)
}

// signing reports whether k is a signing key.
func (k Key) signing() bool { return k.Alg != AlgX25519 }

// check validates the cheap structural rules of chapter 09 §1 and REG-02 that
// a projection relies on. The Source has validated the record; a violation
// here means it did not, and the record is invalid.
func (r Record) check() *Error {
	if err := r.checkHeader(); err != nil {
		return NewError(CodeRecordInvalid, err.Error())
	}
	if err := r.checkKeys(); err != nil {
		return NewError(CodeRecordInvalid, err.Error())
	}
	if err := r.checkServices(); err != nil {
		return NewError(CodeRecordInvalid, err.Error())
	}
	if err := r.Observation.check(); err != nil {
		return NewError(CodeRecordInvalid, err.Error())
	}
	return nil
}

func (r Record) checkHeader() error {
	if r.DID.Method() != "sage" {
		return fmt.Errorf("the record id %q is not a did:sage identifier", r.DID)
	}
	if !ascii(r.Controller, 1, maxControllerLen) {
		return fmt.Errorf("the controller is not 1 to %d ASCII bytes", maxControllerLen)
	}
	switch r.State {
	case StateCreated, StateActive, StateDeactivated:
	default:
		return fmt.Errorf("unknown record state %q", r.State)
	}
	if v, err := strconv.ParseUint(r.Version, 10, 64); err != nil || v == 0 || strconv.FormatUint(v, 10) != r.Version {
		return fmt.Errorf("the version %q is not a canonical decimal from 1", r.Version)
	}
	return nil
}

func (r Record) checkKeys() error {
	if len(r.Keys) == 0 || len(r.Keys) > maxKeys {
		return fmt.Errorf("a record has 1 to %d keys, not %d", maxKeys, len(r.Keys))
	}
	signing := false
	for i, k := range r.Keys {
		if err := k.check(); err != nil {
			return err
		}
		if i > 0 && r.Keys[i-1].Name >= k.Name {
			return fmt.Errorf("keys are not sorted by unique name at %q", k.Name)
		}
		for _, o := range r.Keys[:i] {
			if bytes.Equal(o.Material, k.Material) {
				return fmt.Errorf("the keys %q and %q share key bytes", o.Name, k.Name)
			}
		}
		signing = signing || (k.signing() && k.State == KeyAccepted)
	}
	// REG-02 requires an accepted signing key in an active record; expiry can
	// still leave such a record active but unusable (chapter 09 §3), which
	// projects no key rather than an invalid record.
	if r.State == StateActive && !signing {
		return fmt.Errorf("an active record has no accepted signing key")
	}
	return nil
}

func (k Key) check() error {
	if !keyName.MatchString(k.Name) {
		return fmt.Errorf("the key name %q is not a key-id", k.Name)
	}
	want, ok := map[string]int{AlgEd25519: 32, AlgX25519: 32, AlgP256: 65, AlgSecp256k1: 65}[k.Alg]
	if !ok {
		return fmt.Errorf("the key %q has the unknown algorithm %q", k.Name, k.Alg)
	}
	if len(k.Material) != want || (want == 65 && k.Material[0] != 0x04) {
		return fmt.Errorf("the key %q is not the chapter 11 encoding of %s", k.Name, k.Alg)
	}
	if k.State != KeyAccepted && k.State != KeyRevoked {
		return fmt.Errorf("the key %q has the unknown state %q", k.Name, k.State)
	}
	if k.Expires != nil && (*k.Expires < 0 || *k.Expires > maxExpires) {
		return fmt.Errorf("the key %q has an expiry out of range", k.Name)
	}
	return nil
}

func (r Record) checkServices() error {
	if len(r.Services) > maxServices {
		return fmt.Errorf("a record has at most %d services, not %d", maxServices, len(r.Services))
	}
	for i, s := range r.Services {
		if !keyName.MatchString(s.Name) {
			return fmt.Errorf("the service name %q is not a key-id", s.Name)
		}
		if i > 0 && r.Services[i-1].Name >= s.Name {
			return fmt.Errorf("services are not sorted by unique name at %q", s.Name)
		}
		for _, k := range r.Keys {
			if k.Name == s.Name {
				return fmt.Errorf("the service name %q collides with a key name", s.Name)
			}
		}
		if !ascii(s.Type, 1, maxServiceType) {
			return fmt.Errorf("the service %q type is not 1 to %d ASCII bytes", s.Name, maxServiceType)
		}
		if err := checkServiceURI(s.URI); err != nil {
			return fmt.Errorf("the service %q: %w", s.Name, err)
		}
	}
	return nil
}

// checkServiceURI applies chapter 09 §1: an absolute HTTPS URL of at most
// 2048 ASCII bytes without userinfo or fragment.
func checkServiceURI(s string) error {
	if !ascii(s, 1, maxServiceURI) {
		return fmt.Errorf("the uri is not 1 to %d ASCII bytes", maxServiceURI)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("the uri %q is not an absolute HTTPS URL", s)
	}
	if u.User != nil || u.Fragment != "" || u.RawFragment != "" || bytes.ContainsRune([]byte(s), '#') {
		return fmt.Errorf("the uri %q has userinfo or a fragment", s)
	}
	return nil
}

func (o Observation) check() error {
	if (o.BlockHash == "") == (o.Issued == nil) {
		return fmt.Errorf("an observation has exactly one of a block hash and an issued integer")
	}
	if o.BlockHash != "" && !ascii(o.BlockHash, 1, maxSourceLen) {
		return fmt.Errorf("the block hash is not ASCII")
	}
	if o.Issued != nil && (*o.Issued < 0 || *o.Issued > maxExpires) {
		return fmt.Errorf("the issued integer is out of range")
	}
	if !ascii(o.Source, 1, maxSourceLen) {
		return fmt.Errorf("the source identity is not 1 to %d ASCII bytes", maxSourceLen)
	}
	if o.Time < 0 || o.Time > maxExpires {
		return fmt.Errorf("the observation time is out of range")
	}
	return nil
}

// ascii reports whether s has min to max bytes, all printable ASCII.
func ascii(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
