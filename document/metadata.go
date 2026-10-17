package document

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// Metadata is didDocumentMetadata (DID Resolution v1.0 §4.3, DID Core 1.0
// §7.1.3). It is the only Go type for it: method drivers fill it and
// resolution.DocumentMetadata is an alias. The JSON encoding writes
// Created, Updated and NextUpdate in UTC without sub-second precision.
type Metadata struct {
	Created     *time.Time
	Updated     *time.Time
	Deactivated bool
	// DeactivatedPresent preserves an explicitly supplied false value. A true
	// Deactivated value is always written for compatibility with existing callers.
	// JSON decoding sets this flag for either boolean; the zero value omits it.
	DeactivatedPresent bool
	NextUpdate         *time.Time
	// VersionID and NextVersionID are ASCII strings.
	VersionID     string
	NextVersionID string
	// EquivalentID and CanonicalID are DIDs of the same method as the
	// subject; Check verifies them.
	EquivalentID []string
	CanonicalID  string
	// Proof is a set of proof maps.
	Proof []map[string]any
	// Extra holds properties not listed above, as metadata structure values.
	Extra map[string]any
}

// metadataNames are the JSON names Metadata models.
func metadataNames() []string {
	return []string{"created", "updated", "deactivated", "nextUpdate", "versionId",
		"nextVersionId", "equivalentId", "canonicalId", "proof"}
}

// IsEmpty reports whether m has no property, as required for the metadata
// of an unsuccessful resolution.
func (m Metadata) IsEmpty() bool {
	return m.Created == nil && m.Updated == nil && !m.Deactivated && !m.DeactivatedPresent && m.NextUpdate == nil &&
		m.VersionID == "" && m.NextVersionID == "" && len(m.EquivalentID) == 0 &&
		m.CanonicalID == "" && len(m.Proof) == 0 && len(m.Extra) == 0
}

// Clone returns a deep copy of m.
func (m Metadata) Clone() Metadata {
	c := m
	c.Created, c.Updated, c.NextUpdate = cloneTime(m.Created), cloneTime(m.Updated), cloneTime(m.NextUpdate)
	c.EquivalentID = slices.Clone(m.EquivalentID)
	if m.Proof != nil {
		c.Proof = make([]map[string]any, len(m.Proof))
		for i, p := range m.Proof {
			c.Proof[i] = vm.CloneJSONMap(p)
		}
	}
	c.Extra = vm.CloneJSONMap(m.Extra)
	return c
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// MarshalJSON writes m as a JSON object. Datetimes are converted to UTC and
// truncated to whole seconds (DID Resolution v1.0 §3.1). An Extra key that
// collides with a modeled property, or an Extra value that is not a JSON
// value, is an error.
func (m Metadata) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	for _, k := range metadataNames() {
		if _, ok := m.Extra[k]; ok {
			return nil, fmt.Errorf("document: metadata Extra must not contain %q", k)
		}
	}
	for k, v := range m.Extra {
		if err := vm.CheckJSONValue(v); err != nil {
			return nil, fmt.Errorf("document: metadata %s: %w", k, err)
		}
		out[k] = v
	}
	putTime(out, "created", m.Created)
	putTime(out, "updated", m.Updated)
	putTime(out, "nextUpdate", m.NextUpdate)
	if m.Deactivated || m.DeactivatedPresent {
		out["deactivated"] = m.Deactivated
	}
	putString(out, "versionId", m.VersionID)
	putString(out, "nextVersionId", m.NextVersionID)
	putString(out, "canonicalId", m.CanonicalID)
	if len(m.EquivalentID) > 0 {
		out["equivalentId"] = m.EquivalentID
	}
	if len(m.Proof) > 0 {
		out["proof"] = m.Proof
	}
	return json.Marshal(out)
}

func putTime(out map[string]any, k string, t *time.Time) {
	if t != nil {
		out[k] = spec.FormatTimestamp(*t)
	}
}

func putString(out map[string]any, k, v string) {
	if v != "" {
		out[k] = v
	}
}

// UnmarshalJSON reads a JSON object. Datetimes must be in the format of DID
// Resolution v1.0 §3.1, deactivated must be a boolean, equivalentId an array
// of strings and proof an array of objects. Other members go to Extra, with
// numbers kept as json.Number.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("document: metadata is not a JSON object: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("document: metadata is not a JSON object")
	}
	var out Metadata
	for k, v := range raw {
		if err := out.decodeMember(k, v); err != nil {
			return fmt.Errorf("document: metadata %s: %w", k, err)
		}
	}
	*m = out
	return nil
}

func (m *Metadata) decodeMember(k string, v json.RawMessage) error {
	switch k {
	case "created":
		return decodeTime(v, &m.Created)
	case "updated":
		return decodeTime(v, &m.Updated)
	case "nextUpdate":
		return decodeTime(v, &m.NextUpdate)
	case "deactivated":
		var value *bool
		if err := json.Unmarshal(v, &value); err != nil {
			return err
		}
		if value == nil {
			return fmt.Errorf("must be a boolean, not null")
		}
		m.Deactivated, m.DeactivatedPresent = *value, true
		return nil
	case "versionId":
		return json.Unmarshal(v, &m.VersionID)
	case "nextVersionId":
		return json.Unmarshal(v, &m.NextVersionID)
	case "canonicalId":
		return json.Unmarshal(v, &m.CanonicalID)
	case "equivalentId":
		return json.Unmarshal(v, &m.EquivalentID)
	case "proof":
		return decodeNumbers(v, &m.Proof)
	}
	var x any
	if err := decodeNumbers(v, &x); err != nil {
		return err
	}
	if m.Extra == nil {
		m.Extra = map[string]any{}
	}
	m.Extra[k] = x
	return nil
}

func decodeTime(v json.RawMessage, dst **time.Time) error {
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return err
	}
	t, err := spec.ParseTimestamp(s)
	if err != nil {
		return err
	}
	*dst = &t
	return nil
}

func decodeNumbers(v json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	return dec.Decode(dst)
}

// Check verifies the constraints of DID Resolution v1.0 §4.3 and DID Core
// 1.0 §7.1.3 for the metadata of a document whose subject is subject:
// datetimes without sub-second precision, ASCII version ids, equivalentId and
// canonicalId DIDs of the subject's method, proofs as maps, and metadata
// structure values (numbers are not allowed for spec.V10).
func (m Metadata) Check(subject did.DID, v spec.Version) error {
	for _, t := range []struct {
		name string
		v    *time.Time
	}{{"created", m.Created}, {"updated", m.Updated}, {"nextUpdate", m.NextUpdate}} {
		if t.v != nil && !spec.IsTimestamp(*t.v) {
			return fmt.Errorf("document: metadata %s has sub-second precision or no value", t.name)
		}
	}
	for name, s := range map[string]string{"versionId": m.VersionID, "nextVersionId": m.NextVersionID} {
		if !isASCII(s) {
			return fmt.Errorf("document: metadata %s is not ASCII", name)
		}
	}
	for _, id := range m.EquivalentID {
		if err := sameMethod("equivalentId", id, subject); err != nil {
			return err
		}
	}
	if m.CanonicalID != "" {
		if err := sameMethod("canonicalId", m.CanonicalID, subject); err != nil {
			return err
		}
	}
	for i, p := range m.Proof {
		if p == nil {
			return fmt.Errorf("document: metadata proof[%d] is not a map", i)
		}
		if err := CheckMetadataMap(p, v); err != nil {
			return fmt.Errorf("document: metadata proof[%d]: %w", i, err)
		}
	}
	for _, k := range metadataNames() {
		if _, ok := m.Extra[k]; ok {
			return fmt.Errorf("document: metadata Extra must not contain %q", k)
		}
	}
	return CheckMetadataMap(m.Extra, v)
}

func sameMethod(name, s string, subject did.DID) error {
	d, err := did.Parse(s)
	if err != nil {
		return fmt.Errorf("document: metadata %s %q is not a DID: %w", name, s, err)
	}
	if d.Method() != subject.Method() {
		return fmt.Errorf("document: metadata %s %s is not a DID of method %s", name, d, subject.Method())
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// CheckMetadataMap applies the metadata structure rules (DID Resolution
// v1.0 §metadata-structure, DID Core 1.0 §7.3): string keys, and values that
// are strings, numbers, maps, lists, booleans or null, recursively. DID Core
// 1.0 does not allow numbers, so they are rejected for spec.V10.
func CheckMetadataMap(m map[string]any, v spec.Version) error {
	return checkMetaValue(m, v != spec.V10, 0)
}

func checkMetaValue(x any, numbers bool, depth int) error {
	if depth > maxValueDepth {
		return fmt.Errorf("metadata value nested deeper than %d levels", maxValueDepth)
	}
	switch t := x.(type) {
	case nil, bool:
		return nil
	case string:
		if !utf8.ValidString(t) {
			return fmt.Errorf("metadata string is not valid UTF-8")
		}
		return nil
	case map[string]any:
		for k, e := range t {
			if err := checkMetaValue(e, numbers, depth+1); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		return nil
	case []any:
		for _, e := range t {
			if err := checkMetaValue(e, numbers, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return checkMetaNumber(x, numbers)
}

func checkMetaNumber(x any, numbers bool) error {
	switch t := x.(type) {
	case json.Number, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
	case float32:
		return checkMetaNumber(float64(t), numbers)
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return fmt.Errorf("metadata number is not finite")
		}
	default:
		return fmt.Errorf("type %T is not a metadata structure value", x)
	}
	if !numbers {
		return fmt.Errorf("DID Core 1.0 metadata values must not be numbers")
	}
	return nil
}
