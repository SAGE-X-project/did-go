package conformance

import "testing"

func TestRequirementsAreCopies(t *testing.T) {
	a, err := Requirements()
	if err != nil || len(a) == 0 {
		t.Fatalf("Requirements: %d %v", len(a), err)
	}
	var withParent, withOwner int
	for i := range a {
		if a[i].Parent != nil {
			*a[i].Parent = "changed"
			withParent = i
		}
		if len(a[i].Owners) > 0 {
			a[i].Owners[0] = "changed"
			withOwner = i
		}
	}
	b, _ := Requirements()
	if b[withParent].Parent != nil && *b[withParent].Parent == "changed" {
		t.Fatal("Parent must be copied")
	}
	if len(b[withOwner].Owners) > 0 && b[withOwner].Owners[0] == "changed" {
		t.Fatal("Owners must be copied")
	}
}

func TestDecode(t *testing.T) {
	if _, err := decode([]byte(`{"requirements":`)); err == nil {
		t.Fatal("malformed registry accepted")
	}
	reqs, err := decode([]byte(`{"requirements":[{"id":"example#x.1","scope":"in-scope"}]}`))
	if err != nil || len(reqs) != 1 || reqs[0].ID != "example#x.1" {
		t.Fatalf("got %v %v", reqs, err)
	}
}
