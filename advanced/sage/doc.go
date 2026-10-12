// Package sage is the opt-in SAGE extension of did-go. It presents did:sage
// records, the authoritative identity records of SAGE 0.10.0, as standard
// DID documents and DID Resolution results, following the adopted rules of
// SAGE 0.10.0 chapter 10 (RESOLVE-01 to RESOLVE-05 and DIDP-01 to DIDP-05).
//
// The package decides no trust. Records come from a Source that the
// deployment configures: a SAGE core that acquires a fresh, authorized
// observation and validates the complete record and its proofs. A DID
// document produced here is a view for display and for external DID
// consumers; it is never key authority for a protected SAGE operation
// (DIDP-04), and a created or deactivated record never authorizes one.
//
// The parts are:
//   - Document, Metadata and Produce: the DID Core 1.0 and DID 1.1
//     projections of one record (DIDP-01, DIDP-03) and their metadata
//     (RESOLVE-03);
//   - Select and Respond: the SAGE interface, whose accept table is exact
//     (DIDP-02);
//   - Driver: the did:sage method driver for a standard did-go resolver;
//   - Resolver and Handler: the DID Resolution interface in front of the
//     standard resolver and HTTP(S) binding, with the DIDP-05 error mapping
//     and the sageCode problem member.
//
// The package lives in its own module so that the did-go root module never
// depends on SAGE.
package sage
