package document

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMetadataBooleanPresence(t *testing.T) {
	for _, tt := range []struct {
		name, input    string
		value, present bool
	}{
		{"absent", `{}`, false, false},
		{"false", `{"deactivated":false}`, false, true},
		{"true", `{"deactivated":true}`, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var m Metadata
			if err := json.Unmarshal([]byte(tt.input), &m); err != nil {
				t.Fatal(err)
			}
			if m.Deactivated != tt.value || m.DeactivatedPresent != tt.present || m.IsEmpty() == tt.present {
				t.Fatalf("presence lost: %+v", m)
			}
			for _, actual := range []Metadata{m, m.Clone()} {
				data, err := json.Marshal(actual)
				if err != nil || string(data) != tt.input {
					t.Fatalf("round trip: %s %v", data, err)
				}
			}
			clone := m.Clone()
			clone.Deactivated = true
			clone.DeactivatedPresent = false
			if m.Deactivated != tt.value || m.DeactivatedPresent != tt.present {
				t.Fatal("clone changed original")
			}
		})
	}
	t.Run("constructed values", func(t *testing.T) {
		for _, tt := range []struct {
			m    Metadata
			want string
		}{
			{Metadata{}, `{}`}, {Metadata{Deactivated: true}, `{"deactivated":true}`},
			{Metadata{DeactivatedPresent: true}, `{"deactivated":false}`},
			{Metadata{Deactivated: true, DeactivatedPresent: true}, `{"deactivated":true}`},
		} {
			if !marshalEq(t, tt.m, tt.want) {
				t.Fatalf("%+v", tt.m)
			}
		}
	})
	t.Run("replacement clears presence", func(t *testing.T) {
		m := Metadata{Deactivated: true, DeactivatedPresent: true}
		if err := json.Unmarshal([]byte(`{}`), &m); err != nil || !m.IsEmpty() || m.DeactivatedPresent {
			t.Fatalf("stale presence: %+v %v", m, err)
		}
	})
	t.Run("invalid input leaves destination unchanged", func(t *testing.T) {
		for _, bad := range []string{`null`, `"false"`, `0`, `[]`, `{}`} {
			m := Metadata{Deactivated: true, DeactivatedPresent: true, VersionID: "original"}
			before := m.Clone()
			if err := json.Unmarshal([]byte(`{"deactivated":`+bad+`}`), &m); err == nil {
				t.Fatalf("accepted %s", bad)
			}
			if !reflect.DeepEqual(m, before) {
				t.Fatalf("failed decode changed destination: %s", bad)
			}
		}
	})
}
