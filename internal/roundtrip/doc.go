// Package roundtrip holds the round-trip property tests of the producer and
// consumer players (docs/00 FR-R4, NFR-1): consume(produce(d)) equals d for
// every profile, and produce(consume(b)) equals b for canonical input. The
// players never import each other (docs/14 §2), so the tests that need both
// live here. The package has no code.
package roundtrip
