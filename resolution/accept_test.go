package resolution

import "testing"

func TestNegotiate(t *testing.T) {
	offers := []string{"application/did", "application/did+ld+json", "application/did+json"}
	cases := []struct {
		accept, want string
		ok           bool
	}{
		{"", "application/did", true},
		{" , ", "application/did", true},
		{"application/did+json", "application/did+json", true},
		{"application/*;q=0.5, application/did+ld+json", "application/did+ld+json", true},
		{"*/*;q=0.1, application/did;q=0", "application/did+ld+json", true},
		{"application/did;q=0.4, application/did+json;q=0.8", "application/did+json", true},
		{"application/did+json;q=0.5, application/did;q=0.5", "application/did", true},
		{"application/*;q=0, application/did+json;q=0.2", "application/did+json", true},
		{"application/did+json;charset=utf-8;q=0.3, application/did+json;q=0.9", "application/did+json", true},
		{"text/html", "", false},
		{"*/*;q=0", "", false},
		{"not a range", "", false},
	}
	for _, c := range cases {
		got, ok := Negotiate(c.accept, offers)
		if got != c.want || ok != c.ok {
			t.Errorf("Negotiate(%q) = %q, %v; want %q, %v", c.accept, got, ok, c.want, c.ok)
		}
	}
	if _, ok := Negotiate("", nil); ok {
		t.Fatal("no offer cannot be negotiated")
	}
	if !Acceptable("text/*", "text/uri-list") || Acceptable("text/*;q=0", "text/uri-list") || Acceptable("application/did", "text/uri-list") {
		t.Fatal("Acceptable")
	}
}
