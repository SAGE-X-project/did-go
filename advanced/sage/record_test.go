package sage

import (
	"strings"
	"testing"
)

// Chapter 09 §1 and REG-02: the structural rules a projection relies on.
// Each violation makes the record invalid.
func TestRecordCheck(t *testing.T) {
	if e := activeRecord(t).check(); e != nil {
		t.Fatalf("valid record rejected: %v", e)
	}
	other := mustDID(t, "did:example:123")
	cases := map[string]func(*Record){
		"not did:sage":         func(r *Record) { r.DID = other },
		"empty controller":     func(r *Record) { r.Controller = "" },
		"long controller":      func(r *Record) { r.Controller = strings.Repeat("c", 257) },
		"non-ASCII controller": func(r *Record) { r.Controller = "café" },
		"unknown state":        func(r *Record) { r.State = "paused" },
		"version zero":         func(r *Record) { r.Version = "0" },
		"version leading zero": func(r *Record) { r.Version = "07" },
		"version not decimal":  func(r *Record) { r.Version = "x" },
		"no keys":              func(r *Record) { r.Keys = nil },
		"too many keys": func(r *Record) {
			for len(r.Keys) <= maxKeys {
				r.Keys = append(r.Keys, r.Keys[0])
			}
		},
		"unsorted keys":      func(r *Record) { r.Keys[0], r.Keys[1] = r.Keys[1], r.Keys[0] },
		"duplicate key name": func(r *Record) { r.Keys[1].Name = r.Keys[0].Name },
		"shared key bytes":   func(r *Record) { r.Keys[1].Alg, r.Keys[1].Material = AlgEd25519, xKey },
		"bad key name":       func(r *Record) { r.Keys[0].Name = "a b" },
		"unknown algorithm":  func(r *Record) { r.Keys[0].Alg = "rsa" },
		"short key":          func(r *Record) { r.Keys[0].Material = xKey[:31] },
		"compressed EC key": func(r *Record) {
			r.Keys[0].Alg, r.Keys[0].Material = AlgP256, append([]byte{2}, p256[1:]...)
		},
		"unknown key state": func(r *Record) { r.Keys[0].State = "pending" },
		"negative expiry":   func(r *Record) { r.Keys[0].Expires = issued(-1) },
		"huge expiry":       func(r *Record) { r.Keys[0].Expires = issued(maxExpires + 1) },
		"active without accepted signing key": func(r *Record) {
			r.Keys[1].State = KeyRevoked
		},
		"too many services": func(r *Record) {
			for len(r.Services) <= maxServices {
				r.Services = append(r.Services, r.Services[0])
			}
		},
		"bad service name":     func(r *Record) { r.Services[0].Name = "" },
		"service collides key": func(r *Record) { r.Services[0].Name = "sign" },
		"unsorted services": func(r *Record) {
			r.Services = append(r.Services, Service{Name: "a", Type: "T", URI: "https://a.example"})
		},
		"empty service type":     func(r *Record) { r.Services[0].Type = "" },
		"long service type":      func(r *Record) { r.Services[0].Type = strings.Repeat("t", 65) },
		"http service":           func(r *Record) { r.Services[0].URI = "http://agent.example/a2a" },
		"relative service":       func(r *Record) { r.Services[0].URI = "/a2a" },
		"service userinfo":       func(r *Record) { r.Services[0].URI = "https://u@agent.example/" },
		"service fragment":       func(r *Record) { r.Services[0].URI = "https://agent.example/#x" },
		"empty fragment":         func(r *Record) { r.Services[0].URI = "https://agent.example/#" },
		"long service uri":       func(r *Record) { r.Services[0].URI = "https://agent.example/" + strings.Repeat("a", 2048) },
		"unparsable service uri": func(r *Record) { r.Services[0].URI = "https://agent.example/%zz" },
		"both observation points": func(r *Record) {
			r.Observation.BlockHash = "0xabc"
		},
		"no observation point": func(r *Record) { r.Observation.Issued = nil },
		"bad block hash": func(r *Record) {
			r.Observation.Issued, r.Observation.BlockHash = nil, "\x01"
		},
		"negative issued":  func(r *Record) { r.Observation.Issued = issued(-1) },
		"empty source":     func(r *Record) { r.Observation.Source = "" },
		"negative time":    func(r *Record) { r.Observation.Time = -1 },
		"time beyond bits": func(r *Record) { r.Observation.Time = maxExpires + 1 },
	}
	for name, mutate := range cases {
		r := activeRecord(t)
		r.Keys = append([]Key(nil), r.Keys...)
		r.Services = append([]Service(nil), r.Services...)
		mutate(&r)
		if e := r.check(); e == nil || e.Code != CodeRecordInvalid {
			t.Errorf("%s: %v", name, e)
		}
	}
}

// A created record may have no usable signing key; only an active record
// needs one (REG-02).
func TestCreatedRecordNeedsNoSigningKey(t *testing.T) {
	r := activeRecord(t)
	r.State = StateCreated
	r.Keys = r.Keys[:1]
	if e := r.check(); e != nil {
		t.Errorf("created record rejected: %v", e)
	}
}

// Chapter 09 §3: expiry can leave a record active but unusable. Such a
// record is valid and projects no signing key and no signing relationship.
func TestActiveRecordWithExpiredSigningKey(t *testing.T) {
	r := activeRecord(t)
	r.Keys[1].Expires = issued(testObserved)
	if e := r.check(); e != nil {
		t.Fatalf("rejected: %v", e)
	}
	got := produce(t, r, Core10)
	if strings.Contains(got, "authentication") || strings.Contains(got, "#sign") || !strings.Contains(got, `"keyAgreement":["`+testDID+`#agree"]`) {
		t.Errorf("projection %s", got)
	}
}
