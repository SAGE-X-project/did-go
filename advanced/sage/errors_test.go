package sage

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sage-x-project/did-go/resolution"
)

// DIDP-05: each SAGE code maps to its DID Resolution error type, and the
// SAGE interface keeps the RESOLVE-05 problem type, title and status.
func TestCodeMapping(t *testing.T) {
	cases := []struct {
		code   Code
		mapped resolution.Code
		title  string
		status int
	}{
		{CodeIDMalformed, resolution.CodeInvalidDID, "Malformed identifier", 400},
		{CodeSizeExceeded, resolution.CodeInvalidDID, "Input too large", 413},
		{CodeIDUnknownKind, resolution.CodeMethodNotSupported, "Unsupported registry kind", 400},
		{CodeVersionUnsupported, resolution.CodeInvalidOptions, "Unsupported protocol version", 400},
		{CodeRecordNotFound, resolution.CodeNotFound, "Record not found", 404},
		{CodeKeyNotInRecord, resolution.CodeNotFound, "Key not found", 404},
		{CodeRecordUnreachable, resolution.CodeInternalError, "Registry unavailable", 502},
		{CodeRecordStale, resolution.CodeInternalError, "Registry observation stale", 502},
		{CodeRecordInvalid, resolution.CodeInternalError, "Registry record invalid", 502},
		{CodeRepresentationUnsupported, resolution.CodeFeatureNotSupported, "Unsupported representation", 406},
	}
	for _, c := range cases {
		e := NewError(c.code, "d")
		if got := e.ResolutionError(); got.Type != c.mapped.TypeURL() {
			t.Errorf("%s maps to %s, want %s", c.code, got.Type, c.mapped)
		}
		p := e.Problem()
		if p.Type != ProblemTypePrefix+string(c.code) || p.Title != c.title || p.Status != c.status || p.Detail != "d" {
			t.Errorf("%s problem %+v", c.code, p)
		}
		if !c.code.Valid() {
			t.Errorf("%s not valid", c.code)
		}
	}
	if Code("sig.bad").Valid() {
		t.Error("a message diagnostic is not a resolution code")
	}
	if got := (&Error{Code: "sig.bad"}).ResolutionError(); got.Type != resolution.CodeInternalError.TypeURL() {
		t.Errorf("unknown code maps to %s", got.Type)
	}
}

// DIDP-05: record.stale is never NOT_FOUND, because a stale view is not
// absence; an unexpected source failure is record.unreachable.
func TestCodeOf(t *testing.T) {
	if e := codeOf(NewError(CodeRecordStale, "")); e.Code != CodeRecordStale ||
		e.ResolutionError().Type == resolution.CodeNotFound.TypeURL() {
		t.Errorf("stale: %v", e)
	}
	for _, err := range []error{errors.New("timeout"), NewError("bogus", "")} {
		if e := codeOf(err); e.Code != CodeRecordUnreachable {
			t.Errorf("%v: %v", err, e)
		}
	}
	wrapped := errors.Join(errors.New("x"), NewError(CodeRecordNotFound, ""))
	if e := codeOf(wrapped); e.Code != CodeRecordNotFound {
		t.Errorf("wrapped: %v", e)
	}
}

func TestErrorText(t *testing.T) {
	if NewError(CodeRecordStale, "").Error() != "sage: record.stale" ||
		NewError(CodeRecordStale, "old").Error() != "sage: record.stale: old" {
		t.Error("error text")
	}
	if !errors.Is(NewError(CodeRecordStale, "a"), NewError(CodeRecordStale, "b")) ||
		errors.Is(NewError(CodeRecordStale, ""), NewError(CodeRecordInvalid, "")) ||
		errors.Is(NewError(CodeRecordStale, ""), errors.New("x")) {
		t.Error("Is")
	}
}

// DIDP-05: the problem type is the DID Resolution URL and the SAGE code is
// the sageCode extension member.
func TestProblemJSON(t *testing.T) {
	data, err := ProblemJSON(NewError(CodeRecordNotFound, "gone").ResolutionError(), CodeRecordNotFound)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["type"] != resolution.CodeNotFound.TypeURL() || obj[SageCodeMember] != "record.not-found" {
		t.Errorf("problem %s", data)
	}
	if _, err := ProblemJSON(nil, CodeRecordNotFound); err == nil {
		t.Error("nil error accepted")
	}
	if _, err := ProblemJSON(resolution.NewError(resolution.CodeNotFound, ""), "bogus"); err == nil {
		t.Error("invalid code accepted")
	}
}
