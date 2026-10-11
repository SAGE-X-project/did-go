# X-bar parse schema for normative statements

The meaning check turns every normative statement (from a specification, the
Korean design or the English design) into the same phrase structure, then
compares the structures slot by slot. The structure follows X-bar theory: a
phrase XP has a head X, a specifier and a complement, and adjuncts attach at the
X' level. Applied to a requirement sentence:

```
CP                         condition layer: "if", "when", "unless", "otherwise", "for each"
└── TP                     the requirement itself
    ├── Spec,TP  = DP      the subject that is constrained (who or what must act or be)
    ├── T                  modality and polarity (MUST, SHOULD, MAY, DECL; negated or not)
    └── VP
        ├── V              the predicate, as an English verb lemma
        ├── Comp = DP      the object or predicate value
        └── Adjuncts       scope, manner, time, place, purpose, exception, quantity
```

A DP records its quantifier separately (`each`, `all`, `any`, `exactly-one`,
`at-least-one`, `at-most-one`, `none`, `the`, `a`), because changing "each" to
"any" changes meaning even when the nouns match.

## Output format

One JSON file per batch: a list of objects, one per input unit or statement.

```json
{
  "id": "07-did-resolution-contract.md:12.3",
  "normative": true,
  "claims": [
    {
      "cp": [{"c": "if", "gloss": "the input DID has been deactivated"}],
      "spec": {"q": "the", "head": "did resolver", "gloss": "the DID resolver"},
      "t": {"modality": "MUST", "neg": false},
      "v": "return",
      "comp": {"q": "the", "head": "did document", "gloss": "a null DID document", "value": "null"},
      "adj": [{"role": "scope", "gloss": "in the DID resolution result"}],
      "spec_links": ["res10#resolving-algorithm.26"]
    }
  ]
}
```

Rules for every parser:

1. Glosses are English, lower case, without articles at the start unless the
   quantifier needs them. `head` is the head noun phrase only, singular.
   Korean input is glossed into English; keep technical identifiers (`didDocument`,
   `application/did`, error names) exactly as written.
2. Modality mapping:
   - `MUST`: must, shall, required, 해야 한다, 반드시, 필수, MUST, REQUIRED, SHALL.
   - `MUST` with `neg: true`: must not, shall not, forbidden, 하면 안 된다, 금지, 할 수 없다 (as a prohibition), MUST NOT.
   - `SHOULD` (with `neg` for SHOULD NOT / NOT RECOMMENDED): should, recommended, 권장, 하는 것이 좋다.
   - `MAY`: may, optional, can (as permission), 할 수 있다, 선택, 허용.
   - `DECL`: a plain statement of behavior or fact without a modal ("did-go returns X", "~한다", "~이다"), and algorithm steps written as imperatives.
   Do not upgrade or downgrade: a sentence with "should" is `SHOULD` even if you believe the spec says MUST.
3. One claim per predicate. A table row or sentence that states three rules
   yields three claims, in the order they appear.
4. `cp` lists every condition in order. "Otherwise" is a condition whose gloss
   is the negation of the previous condition.
5. `spec_links` lists ids from the provided specification statement files that
   the claim restates or depends on. Use an empty list when the claim is a
   design decision with no specification counterpart. Do not guess ids.
6. A unit with no requirement or behavioral claim (a title, a pure
   navigation sentence, a rationale with no rule) gets `"normative": false` and
   no claims. When unsure, parse it.
7. Never fix, reinterpret or harmonize the text. Parse what is written.
