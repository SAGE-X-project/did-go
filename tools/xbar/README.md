# X-bar meaning check

The design in `docs/` is translated from a Korean canonical design, and both
restate W3C specifications. An implementation is written from these documents,
so a mistranslated, dropped or misstated rule becomes a defect in code. This
tool checks three relations:

- Korean design and English design say the same thing (translation fidelity);
- each design statement says what the pinned specification says (spec fidelity);
- each normative specification statement is either covered by the design or
  explicitly out of scope (coverage).

## How it works

1. `extract_spec.py` takes a pinned specification HTML file (its SHA-256 must
   match `docs/standards.md`) and extracts every sentence with an RFC 2119
   keyword plus every algorithm step, with its section id, its definition-list
   term and whether it sits in non-normative context.
2. `pair_docs.py` splits the Korean and English documents into units (heading,
   table row, list item, paragraph, code block) and pairs them by position
   inside each heading section. A section whose unit sequence differs is
   reported: something was added or dropped.
3. Independent parsers turn every unit and every specification statement into
   an X-bar structure (`SCHEMA.md`): a condition layer (CP), a subject (Spec),
   modality and polarity (T), a predicate (V), its object (Comp) and adjuncts.
   The Korean and English parsers never see each other's language, so a
   translation that changes meaning yields different structures.
4. `compare.py` builds a graph (units, claims, specification statements;
   edges `translates`, `has-claim`, `restates`) and compares slots. HARD
   findings change meaning for an implementer: normativity, modality, polarity,
   condition count, modality against the linked specification statement, and
   technical tokens in code blocks (identifiers, error codes, numbers). Wording
   differences are SOFT. Normative specification statements that no unit links
   to are listed for the coverage review.
5. Reviewers judge every HARD finding against the original texts
   (`ADJUDICATION.md`) and review every unlinked specification statement as
   COVERED, OUT_OF_SCOPE or GAP. `apply_fixes.py` applies the recorded fixes to
   both languages. After fixes, units whose text changed are parsed again and
   the comparison is repeated until no defect remains.

The parsers and reviewers are language models, so their output is evidence to
be checked, not a verdict by itself. Every defect is confirmed against the
quoted specification text before a document is changed.

## Running

```sh
python3 -I tools/xbar/extract_spec.py res10 PATH/did-resolution-1.0-crd-20261001.html <sha256> > work/res10.json
python3 -I tools/xbar/pair_docs.py KO_DIR docs 00-feature-definition.md ... > work/units.json
# parsers write work/parses/{ko,en,spec}/*.json following SCHEMA.md
python3 -I tools/xbar/compare.py work out
python3 -I tools/xbar/apply_fixes.py work/units.json KO_DIR docs out/verdict-*.json
```

Known limits: the sentence splitter can split a sentence at "OR" lines or
abbreviations; condition-only algorithm steps carry their condition into
child steps by the parser, not by the extractor; and parsers vary in how they
split claims, which is why only the slots listed above are HARD.
