package sage

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sage-x-project/did-go/resolution"
)

// Code is a SAGE diagnostic code (SAGE 0.10.0 chapter 11 TABLE-07) that a
// resolution can fail with.
type Code string

// The codes of the chapter 10 RESOLVE-05 table, which DIDP-05 maps.
const (
	CodeIDMalformed               Code = "id.malformed"
	CodeIDUnknownKind             Code = "id.unknown-kind"
	CodeVersionUnsupported        Code = "version.unsupported"
	CodeRecordNotFound            Code = "record.not-found"
	CodeKeyNotInRecord            Code = "key.not-in-record"
	CodeRecordUnreachable         Code = "record.unreachable"
	CodeRecordStale               Code = "record.stale"
	CodeRecordInvalid             Code = "record.invalid"
	CodeSizeExceeded              Code = "size.exceeded"
	CodeRepresentationUnsupported Code = "representation.unsupported"
)

// ProblemTypePrefix is the prefix of the problem type URI of the SAGE
// interface (chapter 10 RESOLVE-05). The URI is an identifier, never fetched.
const ProblemTypePrefix = "https://sage-x-project.github.io/sage-spec/errors/"

// codeInfo returns the RESOLVE-05 title and status of c and the DID
// Resolution error type DIDP-05 maps it to.
func codeInfo(c Code) (title string, status int, mapped resolution.Code, ok bool) {
	switch c {
	case CodeIDMalformed:
		return "Malformed identifier", 400, resolution.CodeInvalidDID, true
	case CodeIDUnknownKind:
		// DIDP-05: the method is sage; the registry kind is unsupported.
		return "Unsupported registry kind", 400, resolution.CodeMethodNotSupported, true
	case CodeVersionUnsupported:
		return "Unsupported protocol version", 400, resolution.CodeInvalidOptions, true
	case CodeRecordNotFound:
		return "Record not found", 404, resolution.CodeNotFound, true
	case CodeKeyNotInRecord:
		return "Key not found", 404, resolution.CodeNotFound, true
	case CodeRecordUnreachable:
		return "Registry unavailable", 502, resolution.CodeInternalError, true
	case CodeRecordStale:
		// DIDP-05: never NOT_FOUND, because a stale view is not absence.
		return "Registry observation stale", 502, resolution.CodeInternalError, true
	case CodeRecordInvalid:
		return "Registry record invalid", 502, resolution.CodeInternalError, true
	case CodeSizeExceeded:
		return "Input too large", 413, resolution.CodeInvalidDID, true
	case CodeRepresentationUnsupported:
		return "Unsupported representation", 406, resolution.CodeFeatureNotSupported, true
	}
	return "", 0, "", false
}

// Valid reports whether c is a code of the RESOLVE-05 table.
func (c Code) Valid() bool {
	_, _, _, ok := codeInfo(c)
	return ok
}

// Error is a resolution failure with a SAGE code. A Source returns it to
// say why a record cannot be observed.
//
// Detail is public: it appears in problem details. The package never copies
// a Source's Detail there, because RESOLVE-05 keeps internal diagnostics
// behind access controls; the Source's error is kept as Cause, which Error
// and errors.Unwrap expose for local logging.
type Error struct {
	Code   Code
	Detail string
	Cause  error
}

// NewError returns an error with code c and detail.
func NewError(c Code, detail string) *Error { return &Error{Code: c, Detail: detail} }

// Error describes the failure, including its cause, for local logs.
func (e *Error) Error() string {
	s := "sage: " + string(e.Code)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Cause != nil {
		s += ": " + e.Cause.Error()
	}
	return s
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Cause }

// publicDetail is the detail problem details carry: the package's own
// detail, or the RESOLVE-05 title.
func (e *Error) publicDetail() string {
	if e.Detail != "" {
		return e.Detail
	}
	title, _, _, _ := codeInfo(e.Code)
	return title
}

// Is reports whether target is an *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e != nil && t != nil && t.Code == e.Code
}

// codeOf returns the public SAGE error of a Source failure: its code, no
// public detail, and err as the cause. An error that is not an *Error with a
// known code is record.unreachable: the record could not be observed, and
// absence is never assumed (chapter 10 RESOLVE-02 step 4).
func codeOf(err error) *Error {
	var e *Error
	if errors.As(err, &e) && e.Code.Valid() {
		return &Error{Code: e.Code, Cause: err}
	}
	return &Error{Code: CodeRecordUnreachable, Cause: err}
}

// Problem is the RFC 9457 problem details object of the SAGE interface
// (chapter 10 RESOLVE-05): the type is ProblemTypePrefix plus the code, and
// the HTTP status equals Status.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Problem returns the SAGE interface problem of e.
func (e *Error) Problem() Problem {
	title, status, _, _ := codeInfo(e.Code)
	return Problem{Type: ProblemTypePrefix + string(e.Code), Title: title, Status: status, Detail: e.publicDetail()}
}

// ResolutionError returns the DID Resolution error DIDP-05 maps e to. The
// problem type is the DID Resolution URL; the SAGE code travels separately,
// in the sageCode member that ProblemJSON writes.
func (e *Error) ResolutionError() *resolution.Error {
	_, _, mapped, ok := codeInfo(e.Code)
	if !ok {
		mapped = resolution.CodeInternalError
	}
	return resolution.NewError(mapped, e.publicDetail())
}

// SageCodeMember is the problem extension member that carries the SAGE code
// through the DID Resolution interface (DIDP-05).
const SageCodeMember = "sageCode"

// ProblemJSON writes a DID Resolution problem details object with the SAGE
// code in the sageCode member.
func ProblemJSON(e *resolution.Error, c Code) ([]byte, error) {
	if e == nil || !c.Valid() {
		return nil, fmt.Errorf("sage: a resolution error and a valid SAGE code are required")
	}
	obj, err := problemObject(e)
	if err != nil {
		return nil, err
	}
	obj[SageCodeMember] = c
	return json.Marshal(obj)
}

// problemObject returns the members of e as a JSON object.
func problemObject(e *resolution.Error) (map[string]any, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("sage: problem details: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("sage: problem details: %w", err)
	}
	return obj, nil
}
