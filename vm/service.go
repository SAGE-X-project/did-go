package vm

import "slices"

// Service is a service of a DID document (CID 1.0 §2.1.4, DID Core 1.0
// §5.4). It is a plain value: use Clone for an independent copy.
type Service struct {
	// ID is the service id, or "" when absent. CID 1.0 makes it optional;
	// DID Core 1.0 requires it (document.Validate with spec.V10).
	ID string
	// Type is the service type: one string, or a set of strings when it has
	// more than one element.
	Type []string
	// ServiceEndpoint is one endpoint, or a set when it has more than one
	// element.
	ServiceEndpoint []Endpoint
	// Extra holds additional properties (CID 1.0 §2.1.4 "MAY include
	// additional properties"), as JSON values.
	Extra map[string]any
}

// Endpoint is a service endpoint: a URL string or a map. Exactly one of the
// fields is set.
type Endpoint struct {
	// URL is the endpoint string.
	URL string
	// Map is the endpoint map.
	Map map[string]any
}

// Clone returns a deep copy of s.
func (s Service) Clone() Service {
	c := s
	c.Type = slices.Clone(s.Type)
	c.ServiceEndpoint = make([]Endpoint, len(s.ServiceEndpoint))
	for i, e := range s.ServiceEndpoint {
		c.ServiceEndpoint[i] = Endpoint{URL: e.URL, Map: CloneJSONMap(e.Map)}
	}
	if s.ServiceEndpoint == nil {
		c.ServiceEndpoint = nil
	}
	c.Extra = CloneJSONMap(s.Extra)
	return c
}

// Validate applies the CID 1.0 §2.1.4 rules: an id, if present, is a URL;
// type is a string or a set of strings; serviceEndpoint is a string, a map or
// a set of strings and maps; each string is a valid URL. The DID Core 1.0
// rules for id and endpoint strings are applied by document.Validate.
func (s Service) Validate() error {
	if s.ID != "" && !IsURL(s.ID) {
		return errorf("id", "cid10#services.6", "a service id is a URL")
	}
	if err := s.checkType(); err != nil {
		return err
	}
	if err := s.checkEndpoints(); err != nil {
		return err
	}
	return checkExtra(s.Extra, []string{"id", "type", "serviceEndpoint"}, "cid10#services.4")
}

func (s Service) checkType() error {
	if len(s.Type) == 0 {
		return errorf("type", "cid10#services.8", "a service has a type")
	}
	for i, t := range s.Type {
		if t == "" {
			return errorf("type", "cid10#services.9", "a service type is a non-empty string")
		}
		if slices.Contains(s.Type[:i], t) {
			return errorf("type", "cid10#services.9", "a set of types has no duplicates")
		}
	}
	return nil
}

func (s Service) checkEndpoints() error {
	if len(s.ServiceEndpoint) == 0 {
		return errorf("serviceEndpoint", "cid10#services.11", "a service has a serviceEndpoint")
	}
	for _, e := range s.ServiceEndpoint {
		switch {
		case e.URL != "" && e.Map != nil, e.URL == "" && e.Map == nil:
			return errorf("serviceEndpoint", "cid10#services.12", "an endpoint is either a string or a map")
		case e.Map != nil:
			if err := checkJSONMap(e.Map, 1); err != nil {
				return errorf("serviceEndpoint", "cid10#services.12", "%v", err)
			}
		case !IsURL(e.URL):
			return errorf("serviceEndpoint", "cid10#services.13", "an endpoint string is a valid URL")
		}
	}
	return nil
}
