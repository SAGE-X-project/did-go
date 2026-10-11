package resolution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"strings"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// DocumentMetadata is didDocumentMetadata; it is document.Metadata, the type
// method drivers fill, so results pass it on without conversion.
type DocumentMetadata = document.Metadata

// ResolutionMetadata is didResolutionMetadata (DID Resolution v1.0 §4.2);
// the same structure is dereferencingMetadata (§5.2).
type ResolutionMetadata struct {
	// ContentType is the media type of the returned document or content.
	ContentType string
	// Error is set only when the process failed.
	Error *Error
	// Proof is a set of proof maps.
	Proof []map[string]any
	// Extra holds other properties as metadata structure values.
	Extra map[string]any
}

// DereferencingMetadata is dereferencingMetadata (DID Resolution v1.0 §5.2).
type DereferencingMetadata = ResolutionMetadata

func resolutionMetadataNames() []string { return []string{"contentType", "error", "proof"} }

// Validate checks the constraints of DID Resolution v1.0 §4.2 and §5.2 and
// the metadata structure rules for version v: contentType, if present, is an
// ASCII media type; proof is a set of maps; Extra holds metadata structure
// values only (no numbers for spec.V10).
func (m ResolutionMetadata) Validate(v spec.Version) error {
	if m.ContentType != "" {
		if !isASCII(m.ContentType) {
			return fmt.Errorf("resolution: contentType is not ASCII")
		}
		t, _, err := mime.ParseMediaType(m.ContentType)
		typ, sub, ok := strings.Cut(t, "/")
		if err != nil || !ok || !isToken(typ) || !isToken(sub) || strings.Contains(t, "*") {
			return fmt.Errorf("resolution: contentType %q is not a media type", m.ContentType)
		}
	}
	for i, p := range m.Proof {
		if p == nil {
			return fmt.Errorf("resolution: proof[%d] is not a map", i)
		}
		if err := document.CheckMetadataMap(p, v); err != nil {
			return fmt.Errorf("resolution: proof[%d]: %w", i, err)
		}
	}
	for _, n := range resolutionMetadataNames() {
		if _, ok := m.Extra[n]; ok {
			return fmt.Errorf("resolution: Extra must not contain %q", n)
		}
	}
	return document.CheckMetadataMap(m.Extra, v)
}

// MarshalJSON writes the metadata as a JSON object, with error as an RFC
// 9457 object.
func (m ResolutionMetadata) MarshalJSON() ([]byte, error) {
	out, err := extraObject(m.Extra, resolutionMetadataNames())
	if err != nil {
		return nil, err
	}
	putNonEmpty(out, "contentType", m.ContentType)
	if m.Error != nil {
		out["error"] = m.Error
	}
	if len(m.Proof) > 0 {
		out["proof"] = m.Proof
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads a JSON object.
func (m *ResolutionMetadata) UnmarshalJSON(data []byte) error {
	raw, err := rawObject(data)
	if err != nil {
		return err
	}
	var out ResolutionMetadata
	for k, v := range raw {
		switch k {
		case "contentType":
			err = json.Unmarshal(v, &out.ContentType)
		case "error":
			err = json.Unmarshal(v, &out.Error)
		case "proof":
			err = decodeNumbers(v, &out.Proof)
		default:
			out.Extra, err = addExtra(out.Extra, k, v)
		}
		if err != nil {
			return fmt.Errorf("resolution: metadata %s: %w", k, err)
		}
	}
	*m = out
	return nil
}

// extraObject starts a JSON object from Extra, refusing modeled names and
// values that are not JSON values.
func extraObject(extra map[string]any, names []string) (map[string]any, error) {
	out := map[string]any{}
	for _, n := range names {
		if _, ok := extra[n]; ok {
			return nil, fmt.Errorf("resolution: Extra must not contain %q", n)
		}
	}
	for k, v := range extra {
		if err := vm.CheckJSONValue(v); err != nil {
			return nil, fmt.Errorf("resolution: %s: %w", k, err)
		}
		out[k] = v
	}
	return out, nil
}

func putNonEmpty(out map[string]any, k, v string) {
	if v != "" {
		out[k] = v
	}
}

func rawObject(data []byte) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, fmt.Errorf("resolution: not a JSON object")
	}
	return raw, nil
}

func addExtra(extra map[string]any, k string, v json.RawMessage) (map[string]any, error) {
	var x any
	if err := decodeNumbers(v, &x); err != nil {
		return extra, err
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra[k] = x
	return extra, nil
}

func decodeNumbers(v json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	return dec.Decode(dst)
}
