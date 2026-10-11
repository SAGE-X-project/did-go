package dereferencer

import (
	"net/url"
	"slices"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/vm"
)

// services is the service selection branch of DID Resolution §5.4.1.
//
// Services are selected by the service parameter (id match) and the
// serviceType parameter (type match); with both, a service must match both.
// No selected service is NOT_FOUND (did-go policy, as for any URL that
// cannot be dereferenced). The selected DID service endpoint URLs are the
// string endpoints of the selected services, map endpoints skipped; with
// relativeRef each is replaced by the RFC 3986 §5 resolution of relativeRef
// against it. The specification builds that list only when relativeRef is
// present and does not say how it is built for text/uri-list without
// relativeRef; did-go then uses the endpoint URLs unchanged.
//
// Without accept, or when accept prefers a DID document representation, the
// result is the resolved document reduced to the selected services. When it
// prefers text/uri-list the result is the URL list. Anything else is
// REPRESENTATION_NOT_SUPPORTED. For an accept such as */* that accepts both,
// the document is preferred, as the first case of the algorithm.
func (d *Dereferencer) services(params did.DIDParameters, res resolution.Result, opts resolution.DereferenceOptions,
	withFragment bool) resolution.DereferenceResult {
	doc := res.Document
	_, hasService := params.Get(did.ParamService)
	_, hasType := params.Get(did.ParamServiceType)
	var selected []vm.Service
	for _, s := range doc.Services() {
		if hasService && !serviceIDMatches(s.ID, params.Service, doc.ID()) {
			continue
		}
		if hasType && !slices.Contains(s.Type, params.ServiceType) {
			continue
		}
		selected = append(selected, s)
	}
	if len(selected) == 0 {
		return failed(resolution.CodeNotFound, "no service of the DID document matches the service parameters")
	}
	kind := representation.CoreMediaTypes()[0]
	if opts.Accept != "" {
		offers := append(append([]string{res.ResolutionMetadata.ContentType}, representation.CoreMediaTypes()...), MediaTypeURIList)
		var ok bool
		if kind, ok = resolution.Negotiate(opts.Accept, offers); !ok {
			return failed(resolution.CodeRepresentationNotSupported,
				"accept "+opts.Accept+" is neither a DID document representation nor "+MediaTypeURIList)
		}
	}
	if isDIDMediaType(kind) {
		reduced, err := withServices(doc, selected)
		if err != nil {
			return failed(resolution.CodeInternalError, "reducing the services of the document: "+err.Error())
		}
		return d.documentResult(reduced, res, opts, withFragment)
	}
	urls, e := endpointURLs(selected, params)
	if e != nil {
		return resolution.ErrorDereferenceResult(e)
	}
	if len(urls) == 0 {
		return failed(resolution.CodeNotFound, "no selected service has a service endpoint URL")
	}
	return uriList(urls)
}

// uriList returns a text/uri-list result. contentType is written to both
// dereferencingMetadata, which the HTTPS binding reads to answer 303, and
// contentMetadata, where the algorithm puts it (docs/07 caveat 8).
func uriList(urls []string) resolution.DereferenceResult {
	return resolution.DereferenceResult{
		ContentStream:         urls,
		DereferencingMetadata: resolution.DereferencingMetadata{ContentType: MediaTypeURIList},
		ContentMetadata:       resolution.DocumentMetadata{Extra: map[string]any{"contentType": MediaTypeURIList}},
	}
}

// serviceIDMatches reports whether the service id matches the service
// parameter. DID Resolution §5.4.1: "If the id property or the service DID
// parameter or both contain relative references, the corresponding absolute
// URIs MUST be resolved and used for determining the match, using the rules
// specified in RFC3986 Section 5: Reference Resolution and in section
// Relative DID URLs", whose base URI is the DID of the document. The
// specification's Example 13 selects the service "#messages" with
// service=messages, which RFC 3986 resolves to the path /messages instead;
// did-go therefore also matches the parameter taken as a fragment of the DID
// (did-go interpretation of the example).
func serviceIDMatches(id, param string, subject did.DID) bool {
	if id == "" {
		return false
	}
	abs := absoluteRef(id, subject)
	return abs == absoluteRef(param, subject) || abs == absoluteRef("#"+param, subject)
}

// absoluteRef resolves a DID URL reference against subject with RFC 3986 §5
// (did.DIDURL.Resolve); any other string, such as an absolute URL of another
// scheme, is compared as it is.
func absoluteRef(s string, subject did.DID) string {
	u, err := did.ParseReference(s)
	if err != nil {
		return s
	}
	abs, err := u.Resolve(subject.URL())
	if err != nil {
		return s
	}
	return abs.String()
}

// endpointURLs builds the list of selected DID service endpoint URLs: for
// each selected service a map endpoint is skipped and every string endpoint
// is added; with relativeRef, each URL is replaced by the result of RFC 3986
// §5 Reference Resolution with the URL as base and relativeRef as reference
// ("The base URI value is the selected DID service endpoint URL. The relative
// reference is the value of the DID parameter relativeRef."). An
// absolute-path relativeRef therefore replaces the base path, which differs
// from the appended path of Example 14 (docs/07 caveat 6). A relativeRef that
// is not a URI reference is INVALID_DID_URL.
func endpointURLs(selected []vm.Service, params did.DIDParameters) ([]string, *resolution.Error) {
	var urls []string
	for _, s := range selected {
		for _, e := range s.ServiceEndpoint {
			if e.Map == nil {
				urls = append(urls, e.URL)
			}
		}
	}
	if _, ok := params.Get(did.ParamRelativeRef); !ok {
		return urls, nil
	}
	ref, err := url.Parse(params.RelativeRef)
	if err != nil {
		return nil, resolution.NewError(resolution.CodeInvalidDIDURL, "relativeRef is not a URI reference: "+err.Error())
	}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		base, err := url.Parse(u)
		if err != nil {
			return nil, resolution.NewError(resolution.CodeInvalidDIDURL, "a service endpoint is not a URL: "+err.Error())
		}
		out = append(out, base.ResolveReference(ref).String())
	}
	return out, nil
}

// withServices returns a copy of d whose services are exactly services
// (DID Resolution §5.4.1: "Update the services in the resolved DID document
// to contain only the selected services").
func withServices(d *document.Document, services []vm.Service) (*document.Document, error) {
	b := document.NewBuilder(d.ID()).Controller(d.Controllers()...).AlsoKnownAs(d.AlsoKnownAs()...).
		VerificationMethod(d.VerificationMethods()...).Service(services...)
	if d.ControllerShape() != vm.ShapeDefault {
		b.ControllerShape(d.ControllerShape())
	}
	for _, p := range vm.Purposes() {
		if rels := d.Relationship(p); rels != nil {
			b.Relationship(p, rels...)
		}
	}
	for _, e := range d.Extensions().Entries() {
		b.Extension(e.Key, e.Value)
	}
	for _, e := range d.RepresentationEntries().Entries() {
		b.RepresentationEntry(e.Key, e.Value)
	}
	return b.Build()
}
