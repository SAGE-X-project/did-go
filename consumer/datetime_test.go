package consumer

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/representation"
)

func TestKeyTimestampInputs(t *testing.T) {
	fields := []struct{ name, statement string }{
		{"expires", "cid10#verification-methods.9"},
		{"revoked", "cid10#verification-methods.11"},
	}
	valid := []struct {
		text    string
		instant time.Time
		offset  int
	}{
		{"2030-01-01T00:00:00Z", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"2030-01-01T09:00:00.500000001+09:00", time.Date(2030, 1, 1, 0, 0, 0, 500000001, time.UTC), 9 * 3600},
		{"2029-12-31T19:00:00.5-05:00", time.Date(2030, 1, 1, 0, 0, 0, 500000000, time.UTC), -5 * 3600},
		{"2030-01-01T14:00:00+14:00", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 14 * 3600},
		{"2029-12-31T10:00:00-14:00", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), -14 * 3600},
		{"2030-01-01T00:00:00+00:00", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"2030-01-01T13:59:00+13:59", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 13*3600 + 59*60},
		{"2029-12-31T10:01:00-13:59", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), -(13*3600 + 59*60)},
		{"2032-02-29T00:00:00.000000001Z", time.Date(2032, 2, 29, 0, 0, 0, 1, time.UTC), 0},
	}
	invalid := []any{
		false, 7, nil, "2030-01-01T00:00:00", "2030-01-01", "2030-02-30T00:00:00Z",
		"2030-01-01T00:00:00,5Z", "2030-01-01T00:00:00+14:01", "2030-01-01T00:00:00-14:01",
		"2030-01-01T00:00:00+13:60", "2030-01-01T00:00:00-13:60",
		"2030-01-01T00:00:00+00:60", "2030-01-01T00:00:00-00:60",
		"2030-01-01T00:00:00+15:00", "2030-01-01T00:00:00-15:00",
		"2030-01-01T0:00:00Z", "2030-01-01T00:00:00.Z", "2030-01-01T00:00:00+01:0",
		"2030-01-01T00:00:00Zsuffix", "2030-01-01T00:00:60Z",
	}
	for _, media := range []string{"application/did", "application/did+json"} {
		for _, field := range fields {
			t.Run(media+"/"+field.name, func(t *testing.T) {
				for _, v := range valid {
					t.Run(v.text, func(t *testing.T) {
						input := timestampDocument(t, field.name, v.text)
						doc, _, err := New().Consume(input, media, representation.ConsumeOptions{})
						if err != nil || doc == nil {
							t.Fatalf("valid timestamp: doc=%v err=%v", doc, err)
						}
						method := doc.VerificationMethods()[0]
						got := method.Expires
						if field.name == "revoked" {
							got = method.Revoked
						}
						if got == nil || !got.Equal(v.instant) {
							t.Fatalf("timestamp=%v want=%v", got, v.instant)
						}
						_, offset := got.Zone()
						if offset != v.offset {
							t.Fatalf("offset=%d want=%d", offset, v.offset)
						}
					})
				}
				for i, v := range invalid {
					t.Run(fmt.Sprintf("invalid-%02d", i), func(t *testing.T) {
						input := timestampDocument(t, field.name, v)
						doc, _, err := New().Consume(input, media, representation.ConsumeOptions{})
						if doc != nil {
							t.Fatalf("invalid timestamp returned a document: %s", input)
						}
						wantConsumerError(t, err, field.statement)
					})
				}
			})
		}
	}
}

func timestampDocument(t *testing.T, field string, value any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"id": "did:example:clock",
		"verificationMethod": []any{map[string]any{
			"id": "did:example:clock#key", "type": "Multikey", "controller": "did:example:clock", field: value,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
