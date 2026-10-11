package wire

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/document"
)

func mustParse(t *testing.T, s string) Node {
	t.Helper()
	n, err := Parse([]byte(s), Limits{})
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return n
}

func wantParseError(t *testing.T, s string, lim Limits, reason string) {
	t.Helper()
	_, err := Parse([]byte(s), lim)
	var we *Error
	if !errors.As(err, &we) || !strings.Contains(we.Reason, reason) || !strings.Contains(err.Error(), "offset") {
		t.Fatalf("Parse(%q) = %v, want an error containing %q", s, err, reason)
	}
}

func TestParseValid(t *testing.T) {
	n := mustParse(t, " {\"b\":[1,-2.5e3,true,false,null,\"x\"],\"a\":{} ,\"c\":[]}\n")
	if n.Kind != Object || len(n.Members) != 3 || n.Members[0].Name != "b" || n.Members[1].Name != "a" {
		t.Fatalf("member order must be kept: %+v", n)
	}
	b, _ := n.Get("b")
	if b.Items[0].Text != "1" || b.Items[1].Text != "-2.5e3" || !b.Items[2].Bool || b.Items[3].Bool || b.Items[4].Kind != Null {
		t.Fatalf("items %+v", b.Items)
	}
	if _, ok := n.Get("missing"); ok {
		t.Fatal("Get of a missing member")
	}
	s := mustParse(t, `"\"\\\/\b\f\n\r\té😀é"`)
	if s.Text != "\"\\/\b\f\n\r\té😀é" {
		t.Fatalf("escapes: %q", s.Text)
	}
	for _, num := range []string{"0", "-0", "0.5", "1E+2", "1e-2", "123"} {
		if n := mustParse(t, num); n.Kind != Number || n.Text != num {
			t.Fatalf("%s: %+v", num, n)
		}
	}
}

func TestParseRejects(t *testing.T) {
	t.Run("duplicate members are rejected", func(t *testing.T) {
		wantParseError(t, `{"id":"a","id":"b"}`, Limits{}, "duplicate member")
		mustParse(t, `{"a":{"id":1},"b":{"id":2}}`)
	})
	t.Run("invalid UTF-8 is rejected", func(t *testing.T) {
		wantParseError(t, "{\"a\":\"\xff\"}", Limits{}, "UTF-8")
		wantParseError(t, `"\ud800"`, Limits{}, "lone surrogate")
		wantParseError(t, `"\udc00\udc00"`, Limits{}, "lone surrogate")
		wantParseError(t, `"\ud800A"`, Limits{}, "lone surrogate")
		wantParseError(t, `"\ud800x"`, Limits{}, "lone surrogate")
	})
	t.Run("size and depth limits", func(t *testing.T) {
		wantParseError(t, `[1,2,3]`, Limits{MaxBytes: 4}, "larger than 4 bytes")
		wantParseError(t, `[[[1]]]`, Limits{MaxDepth: 2}, "deeper than 2")
		wantParseError(t, `{"a":{"b":1}}`, Limits{MaxDepth: 1}, "deeper than 1")
		mustParse(t, strings.Repeat("[", DefaultMaxDepth)+strings.Repeat("]", DefaultMaxDepth))
		wantParseError(t, strings.Repeat("[", DefaultMaxDepth+1)+strings.Repeat("]", DefaultMaxDepth+1), Limits{}, "deeper")
		big := `"` + strings.Repeat("a", DefaultMaxBytes) + `"`
		wantParseError(t, big, Limits{}, "larger")
	})
	t.Run("syntax errors", func(t *testing.T) {
		for in, reason := range map[string]string{
			``: "end of input", `{`: "member name", `{"a"`: "':'", `{"a":`: "end of input", `{"a":1`: "end of input",
			`{"a":1 x`: "expected ','", `[1 2]`: "expected ','", `[1,]`: "invalid character", `{1:2}`: "member name",
			`tru`: "invalid character", `nul`: "invalid character", `01`: "after the JSON value", `-`: "invalid number",
			`1.`: "after '.'", `1e`: "exponent", `1e+`: "exponent", `"abc`: "unterminated string", "\"\t\"": "control character",
			`"\x"`: "invalid escape", `"\`: "unterminated escape", `"\u12"`: "short", `"\u12zz"`: "invalid \\u escape",
			`"\ud800\u12"`: "short", `{} {}`: "after the JSON value", `[`: "end of input",
		} {
			wantParseError(t, in, Limits{}, reason)
		}
	})
}

func TestKind(t *testing.T) {
	for k, want := range map[Kind]string{Null: "null", Bool: "boolean", Number: "number", String: "string", Array: "array", Object: "object"} {
		if k.String() != want {
			t.Errorf("%d: %s", k, k.String())
		}
	}
}

func TestEncode(t *testing.T) {
	in := `{"b":[1,-2.5e3,true,false,null,"x"],"a":{},"c":[],"s":"q\"\\\n\r\t\b\f\u0001<>&é😀"}`
	if got := string(Encode(mustParse(t, in))); got != in {
		t.Fatalf("Encode:\n got %s\nwant %s", got, in)
	}
	n := Node{Kind: Kind(42)}
	if string(Encode(n)) != "null" {
		t.Fatal("unknown kind writes null")
	}
}

func TestToValue(t *testing.T) {
	t.Run("did11-cr20260305#consumption.1 integers, doubles, strings, lists and maps", func(t *testing.T) {
		v, err := ToValue(mustParse(t, `{"i":42,"d":1.5,"e":1e3,"s":"2020-12-20T19:17:47Z","b":true,"n":null,"l":[1,"a"]}`))
		if err != nil {
			t.Fatal(err)
		}
		m := v.(document.Map)
		if !equalKeys(m.Keys(), []string{"i", "d", "e", "s", "b", "n", "l"}) {
			t.Fatalf("order %v", m.Keys())
		}
		for k, want := range map[string]document.Value{"i": document.Integer(42), "d": document.Double(1.5), "e": document.Double(1000),
			"s": document.String("2020-12-20T19:17:47Z"), "b": document.Boolean(true), "n": document.Null{}} {
			if got, _ := m.Get(k); got != want {
				t.Errorf("%s = %#v, want %#v", k, got, want)
			}
		}
		l, _ := m.Get("l")
		if l.(document.List).Len() != 2 {
			t.Fatal("list")
		}
	})
	t.Run("numbers outside the model are errors, not lossy", func(t *testing.T) {
		for _, in := range []string{`9223372036854775808`, `[1e400]`, `{"a":-9223372036854775809}`} {
			if _, err := ToValue(mustParse(t, in)); err == nil {
				t.Errorf("%s accepted", in)
			}
		}
		if _, err := ToValue(Node{Kind: Kind(9)}); err == nil {
			t.Fatal("unknown kind accepted")
		}
	})
}

func equalKeys(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

func TestFromValue(t *testing.T) {
	t.Run("did11-cr20260305#production.1 data types map to JSON types", func(t *testing.T) {
		loc := time.FixedZone("x", 9*3600)
		l, _ := document.NewList(document.Integer(-7), document.Double(2), document.Double(0.25), document.Double(1e21),
			document.Boolean(false), document.Null{}, document.NewDateTime(time.Date(2020, 12, 21, 4, 17, 47, 5, loc)))
		m, _ := document.NewMap(document.Entry{Key: "z", Value: l}, document.Entry{Key: "a", Value: document.String("é")})
		n, err := FromValue(m)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"z":[-7,2.0,0.25,1.0e+21,false,null,"2020-12-20T19:17:47Z"],"a":"é"}`
		if got := string(Encode(n)); got != want {
			t.Fatalf("got %s\nwant %s", got, want)
		}
		back, err := ToValue(mustParse(t, want))
		if err != nil {
			t.Fatal(err)
		}
		bl, _ := back.(document.Map).Get("z")
		if bl.(document.List).At(1) != document.Double(2) || bl.(document.List).At(0) != document.Integer(-7) {
			t.Fatal("integer and double must survive a round trip")
		}
	})
	t.Run("values the model cannot write are errors", func(t *testing.T) {
		for _, v := range []document.Value{document.Double(math.NaN()), document.String("\xff"), document.NewDateTime(time.Time{})} {
			if _, err := FromValue(v); err == nil {
				t.Errorf("%#v accepted", v)
			}
		}
	})
	for f, want := range map[float64]string{1: "1.0", -3: "-3.0", 0.5: "0.5", 1e21: "1.0e+21", 1.5e-7: "1.5e-07", 123456789: "1.23456789e+08"} {
		if got := FormatDouble(f); got != want {
			t.Errorf("FormatDouble(%v) = %s, want %s", f, got, want)
		}
	}
}

func TestAny(t *testing.T) {
	n := mustParse(t, `{"kty":"OKP","n":1.50,"l":[null,true,"x",{"b":1,"a":2}]}`)
	v := ToAny(n).(map[string]any)
	if v["n"] != json.Number("1.50") || v["l"].([]any)[0] != nil {
		t.Fatalf("ToAny %v", v)
	}
	back, err := FromAny(v)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(Encode(back)); got != `{"kty":"OKP","l":[null,true,"x",{"a":2,"b":1}],"n":1.50}` {
		t.Fatalf("FromAny must sort keys and keep number text: %s", got)
	}
	gonums, err := FromAny([]any{1, int64(-2), uint8(3), 2.5, float32(0.5), 1e21})
	if err != nil || string(Encode(gonums)) != `[1,-2,3,2.5,0.5,1e+21]` {
		t.Fatalf("Go numbers: %s %v", Encode(gonums), err)
	}
	for _, bad := range []any{json.Number("1.2.3"), json.Number(""), map[string]any{"a": json.Number("x")}, []any{json.Number("01")}, math.Inf(1), struct{}{}} {
		if _, err := FromAny(bad); err == nil {
			t.Errorf("%#v accepted", bad)
		}
	}
}

func TestNames(t *testing.T) {
	if !IsDocumentProperty("service") || IsDocumentProperty("type") {
		t.Fatal("IsDocumentProperty")
	}
	if !IsSecretProperty(PropSecretKeyJwk) || !IsSecretProperty(PropSecretKeyMultibase) || IsSecretProperty(PropPublicKeyJwk) {
		t.Fatal("IsSecretProperty")
	}
	if len(DocumentProperties()) != 10 || len(MethodProperties()) != 9 || len(ServiceProperties()) != 3 {
		t.Fatal("tables")
	}
	p := DocumentProperties()
	p[0] = "x"
	if DocumentProperties()[0] != PropID {
		t.Fatal("tables must be fresh")
	}
}
