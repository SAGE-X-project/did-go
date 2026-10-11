package vm

import (
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

// maxDepth bounds the nesting of JSON values held in Extra, JWK and endpoint
// maps (docs/12 §6.3).
const maxDepth = 64

// CheckJSONValue reports whether v can be serialized as JSON without loss:
// nil, bool, a valid UTF-8 string, a finite number (Go numeric types or
// json.Number), []any or map[string]any of such values, nested at most 64
// levels.
func CheckJSONValue(v any) error {
	return checkJSON(v, 0)
}

func checkJSON(v any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("value nested deeper than %d levels", maxDepth)
	}
	switch x := v.(type) {
	case nil, bool, json.Number,
		int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case string:
		if !utf8.ValidString(x) {
			return fmt.Errorf("string is not valid UTF-8")
		}
		return nil
	case float64:
		return checkFloat(x)
	case float32:
		return checkFloat(float64(x))
	case []any:
		for _, e := range x {
			if err := checkJSON(e, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		return checkJSONMap(x, depth+1)
	}
	return fmt.Errorf("type %T is not a JSON value", v)
}

func checkJSONMap(m map[string]any, depth int) error {
	for k, e := range m {
		if !utf8.ValidString(k) {
			return fmt.Errorf("key is not valid UTF-8")
		}
		if err := checkJSON(e, depth); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func checkFloat(f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("number is not finite")
	}
	return nil
}

// CloneJSONValue returns a deep copy of a JSON value built from []any and
// map[string]any; other values are returned as they are.
func CloneJSONValue(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = CloneJSONValue(e)
		}
		return out
	case map[string]any:
		return CloneJSONMap(x)
	}
	return v
}

// CloneJSONMap returns a deep copy of m, or nil when m is nil.
func CloneJSONMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = CloneJSONValue(v)
	}
	return out
}

// checkExtra checks the additional properties of a map: no modeled name and
// only JSON values.
func checkExtra(extra map[string]any, modeled []string, statement string) error {
	for _, name := range modeled {
		if _, ok := extra[name]; ok {
			return errorf(name, statement, "a modeled property must not be set through Extra")
		}
	}
	if err := checkJSONMap(extra, 1); err != nil {
		return errorf("extra", statement, "%v", err)
	}
	return nil
}
