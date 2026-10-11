package resolution

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
)

// ResolutionOptions are the input options of resolve (DID Resolution v1.0
// §4.1, §13.2).
type ResolutionOptions struct {
	// Accept is the preferred representation as an HTTP Accept value.
	Accept string
	// ExpandRelativeURLs asks for relative DID URLs to be made absolute.
	ExpandRelativeURLs bool
	// VersionID selects a document version.
	VersionID string
	// VersionTime selects the latest version before this time. It must be
	// UTC without sub-second precision; it is checked, not corrected.
	VersionTime *time.Time
	// NoCache asks for a fresh document instead of a cached one.
	NoCache bool
	// Extra holds extension options as metadata structure values.
	Extra map[string]any
}

// DereferenceOptions are the input options of dereference (DID Resolution
// v1.0 §5.1).
type DereferenceOptions struct {
	// Accept is the preferred content type as an HTTP Accept value.
	Accept string
	// VerificationRelationship is the relationship the dereferenced method
	// must be authorized for, for example "authentication".
	VerificationRelationship string
	// Extra holds extension options as metadata structure values.
	Extra map[string]any
}

func invalidOptions(format string, args ...any) *Error {
	return NewError(CodeInvalidOptions, fmt.Sprintf(format, args...))
}

// Validate returns an INVALID_OPTIONS error when an option is malformed:
// Accept that is not an RFC 9110 Accept value, a non-ASCII versionId, a
// versionTime with an offset other than UTC or with sub-second precision, or
// Extra that shadows a modeled option or holds a value a metadata structure
// cannot hold.
func (o ResolutionOptions) Validate() *Error {
	if _, err := ParseAccept(o.Accept); err != nil {
		return invalidOptions("accept: %v", err)
	}
	if !isASCII(o.VersionID) {
		return invalidOptions("versionId is not ASCII")
	}
	if t := o.VersionTime; t != nil {
		if _, off := t.Zone(); off != 0 || !spec.IsTimestamp(*t) {
			return invalidOptions("versionTime must be UTC without sub-second precision")
		}
	}
	return checkExtra(o.Extra, resolutionOptionNames())
}

// Validate returns an INVALID_OPTIONS error for an Accept value that is not
// an RFC 9110 Accept value, a non-ASCII verificationRelationship, or invalid
// Extra.
func (o DereferenceOptions) Validate() *Error {
	if _, err := ParseAccept(o.Accept); err != nil {
		return invalidOptions("accept: %v", err)
	}
	if !isASCII(o.VerificationRelationship) {
		return invalidOptions("verificationRelationship is not ASCII")
	}
	return checkExtra(o.Extra, []string{"accept", "verificationRelationship"})
}

func resolutionOptionNames() []string {
	return []string{"accept", "expandRelativeUrls", "versionId", "versionTime", "noCache"}
}

func checkExtra(extra map[string]any, names []string) *Error {
	for _, n := range names {
		if _, ok := extra[n]; ok {
			return invalidOptions("Extra must not contain %q", n)
		}
	}
	if err := document.CheckMetadataMap(extra, spec.V11); err != nil {
		return invalidOptions("%v", err)
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

// MarshalJSON writes the options as a JSON object; versionTime uses the
// datetime format of DID Resolution v1.0 §3.1.
func (o ResolutionOptions) MarshalJSON() ([]byte, error) {
	out, err := extraObject(o.Extra, resolutionOptionNames())
	if err != nil {
		return nil, err
	}
	putNonEmpty(out, "accept", o.Accept)
	putNonEmpty(out, "versionId", o.VersionID)
	if o.ExpandRelativeURLs {
		out["expandRelativeUrls"] = true
	}
	if o.NoCache {
		out["noCache"] = true
	}
	if o.VersionTime != nil {
		out["versionTime"] = spec.FormatTimestamp(*o.VersionTime)
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads a JSON object. versionTime must already be in the
// datetime format; the booleans must be JSON booleans.
func (o *ResolutionOptions) UnmarshalJSON(data []byte) error {
	raw, err := rawObject(data)
	if err != nil {
		return err
	}
	var out ResolutionOptions
	for k, v := range raw {
		switch k {
		case "accept":
			err = json.Unmarshal(v, &out.Accept)
		case "versionId":
			err = json.Unmarshal(v, &out.VersionID)
		case "expandRelativeUrls":
			err = json.Unmarshal(v, &out.ExpandRelativeURLs)
		case "noCache":
			err = json.Unmarshal(v, &out.NoCache)
		case "versionTime":
			out.VersionTime, err = decodeTimestamp(v)
		default:
			out.Extra, err = addExtra(out.Extra, k, v)
		}
		if err != nil {
			return fmt.Errorf("resolution: option %s: %w", k, err)
		}
	}
	*o = out
	return nil
}

// MarshalJSON writes the options as a JSON object.
func (o DereferenceOptions) MarshalJSON() ([]byte, error) {
	out, err := extraObject(o.Extra, []string{"accept", "verificationRelationship"})
	if err != nil {
		return nil, err
	}
	putNonEmpty(out, "accept", o.Accept)
	putNonEmpty(out, "verificationRelationship", o.VerificationRelationship)
	return json.Marshal(out)
}

// UnmarshalJSON reads a JSON object.
func (o *DereferenceOptions) UnmarshalJSON(data []byte) error {
	raw, err := rawObject(data)
	if err != nil {
		return err
	}
	var out DereferenceOptions
	for k, v := range raw {
		switch k {
		case "accept":
			err = json.Unmarshal(v, &out.Accept)
		case "verificationRelationship":
			err = json.Unmarshal(v, &out.VerificationRelationship)
		default:
			out.Extra, err = addExtra(out.Extra, k, v)
		}
		if err != nil {
			return fmt.Errorf("resolution: option %s: %w", k, err)
		}
	}
	*o = out
	return nil
}

func decodeTimestamp(v json.RawMessage) (*time.Time, error) {
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, err
	}
	t, err := spec.ParseTimestamp(s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
