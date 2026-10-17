# Key timestamp input validation

CID 1.0 verification-methods.9 and verification-methods.11 assign XML Schema
`dateTimeStamp` to `expires` and `revoked`. The consumer checks the supported
four-digit-year lexical form before calendar parsing. It rejects comma fractions,
single-digit hours, timezone minutes outside 00–59, offsets beyond ±14:00, and
nonzero minutes at the fourteen-hour boundary. This follows
[XSD 1.1 Part 2, 5 April 2012, sections 3.3.7.2 and 3.4.28](https://www.w3.org/TR/2012/REC-xmlschema11-2-20120405/).

The Go RFC3339 parser alone accepts some of those invalid forms. Testing the
parsed timezone offset alone is insufficient: a minute value of 60 can normalize
to the next hour. The consumer checks the input spelling, then lets the parser
check the calendar. A rejected timestamp returns a consumer error naming its
field requirement and no document. Valid offsets and nanosecond fractions retain
their values. This input check does not implement key expiry or revocation policy.

## Remaining representation limits

This repair is not complete XML Schema `dateTimeStamp` support. The existing Go
model and parsing path have separate limitations for end-of-day `24:00:00`, zero,
negative or expanded years, whitespace mapping, and fractions beyond nanosecond
precision. In particular, the existing Go parser truncates longer fractions;
this repair does not establish lossless handling of those values. Their lexical
validity, representability and error contracts need separate review. Valid XSD
forms must not be relabeled invalid merely to fit the current model, and no full
schema conformance claim follows from these selected controls.

DID Resolution metadata uses a different UTC whole-second contract in
`spec.ParseTimestamp`. Reusing that parser for key timestamps would reject valid
offsets and fractions, so it is not used here. The SAGE record's integer timestamp
fields are also unchanged.
