package representation

import (
	"fmt"

	"github.com/sage-x-project/did-go/spec"
)

// Context describes the @context entry of a payload for detection.
type Context struct {
	// Present is true when the root map has an @context entry.
	Present bool
	// First is the first @context value when it is a string ("" otherwise).
	First string
}

// nonStringContext is recorded as UnexpectedContext when the first @context
// value is not a string.
const nonStringContext = "(first @context value is not a string)"

// DetectError reports input that the detection rule rejects. Step is the
// step of docs/09 §4 that failed (1 to 5), or 6 for ConsumeOptions.Require.
type DetectError struct {
	Step   int
	Reason string
}

// Error describes the failure.
func (e *DetectError) Error() string {
	return fmt.Sprintf("representation: detection step %d: %s", e.Step, e.Reason)
}

func detectErr(step int, format string, args ...any) *DetectError {
	return &DetectError{Step: step, Reason: fmt.Sprintf(format, args...)}
}

// Detect applies the detection rule of docs/09 §4 and docs/12 §6.1 to a
// declared media type and the @context of the payload:
//
//  1. application/did+json is V10 JSON; a first @context value other than
//     the DID Core 1.0 context is recorded in UnexpectedContext (an error
//     under Strict).
//  2. application/did+ld+json is V10 JSON-LD; @context is required and its
//     first value must be https://www.w3.org/ns/did/v1.
//  3. application/did is V11; a present @context must start with
//     https://www.w3.org/ns/did/v1.1.
//  4. application/json and application/ld+json are decided by the payload:
//     the first @context value gives V11 or V10; without @context the
//     version is opts.Expected or VUnknown and Assumed is set. LowPrecision
//     is recorded. Under Strict this step is an error.
//  5. Any other media type, no media type, or another first @context value
//     in steps 2 to 4 is an error.
//
// Finally a version other than opts.Require (when set) is an error.
func Detect(mediaType string, ctx Context, opts ConsumeOptions) (ConsumeInfo, error) {
	if mediaType == "" {
		return ConsumeInfo{}, detectErr(5, "a consumer takes a media type as input")
	}
	mt, err := NormalizeMediaType(mediaType)
	if err != nil {
		return ConsumeInfo{}, detectErr(5, "%v", err)
	}
	var info ConsumeInfo
	switch {
	case mt == spec.MediaTypeDIDJSON:
		info, err = detectDIDJSON(ctx, opts)
	case mt == spec.MediaTypeDIDLDJSON:
		info, err = detectDeclared(2, spec.V10, ctx, true)
	case mt == spec.MediaTypeDID:
		info, err = detectDeclared(3, spec.V11, ctx, ctx.Present)
	case IsLowPrecision(mt):
		info, err = detectLowPrecision(mt, ctx, opts)
	default:
		return ConsumeInfo{}, detectErr(5, "%q is not a DID or low-precision media type", mt)
	}
	if err != nil {
		return ConsumeInfo{}, err
	}
	if opts.Require != spec.VUnknown && info.DetectedVersion != opts.Require {
		return ConsumeInfo{}, detectErr(6, "detected version %s, required %s", info.DetectedVersion, opts.Require)
	}
	return info, nil
}

func detectDIDJSON(ctx Context, opts ConsumeOptions) (ConsumeInfo, error) {
	info := ConsumeInfo{DetectedVersion: spec.V10}
	if ctx.Present && !isContextOf(ctx.First, spec.V10) {
		info.UnexpectedContext = ctx.First
		if ctx.First == "" {
			info.UnexpectedContext = nonStringContext
		}
		if opts.Strict {
			return ConsumeInfo{}, detectErr(1, "unexpected @context %q under application/did+json", info.UnexpectedContext)
		}
	}
	return info, nil
}

// detectDeclared handles steps 2 and 3, where the media type fixes the
// version and a present @context must start with that version's context.
func detectDeclared(step int, v spec.Version, ctx Context, jsonld bool) (ConsumeInfo, error) {
	if step == 2 && !ctx.Present {
		return ConsumeInfo{}, detectErr(2, "application/did+ld+json requires @context")
	}
	if ctx.Present && !isContextOf(ctx.First, v) {
		return ConsumeInfo{}, detectErr(step, "the first @context value must be the DID %s context", v)
	}
	return ConsumeInfo{DetectedVersion: v, IsJSONLD: jsonld}, nil
}

func detectLowPrecision(mt string, ctx Context, opts ConsumeOptions) (ConsumeInfo, error) {
	if opts.Strict {
		return ConsumeInfo{}, detectErr(4, "strict consumption does not decide %s input from its payload", mt)
	}
	var info ConsumeInfo
	switch {
	case ctx.Present && isContextOf(ctx.First, spec.V11):
		info = ConsumeInfo{DetectedVersion: spec.V11, IsJSONLD: true}
	case ctx.Present && isContextOf(ctx.First, spec.V10):
		info = ConsumeInfo{DetectedVersion: spec.V10, IsJSONLD: true}
	case ctx.Present:
		return ConsumeInfo{}, detectErr(5, "the first @context value is not a DID base context")
	case opts.Expected != spec.VUnknown && !opts.Expected.IsSupported():
		return ConsumeInfo{}, detectErr(4, "expected version %d is not supported", int(opts.Expected))
	default:
		info = ConsumeInfo{DetectedVersion: opts.Expected, Assumed: true}
	}
	info.LowPrecision = &LowPrecision{Declared: mt, Detected: MediaTypeOf(info)}
	return info, nil
}
