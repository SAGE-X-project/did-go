# Adjudication of comparison findings

`compare.py` marks differences between independent parses. A difference can
come from the documents or from the parsers, so every HARD finding is judged by
a reviewer who reads the original texts. The reviewer never trusts a parse over
the text.

## Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| `TRANSLATION_DEFECT` | The Korean and English texts say different things (strength, polarity, condition, subject, object, number, identifier). | Fix the English, or the Korean when the Korean is wrong against the specification. |
| `SPEC_DEFECT` | The design text (both languages) misstates, weakens, strengthens or omits part of the pinned specification statement it relies on, and does not say that it deviates on purpose. | Fix both languages; quote the specification. |
| `BOTH_DEFECT` | Both of the above. | Both fixes. |
| `INTENDED_DESIGN` | The design deliberately differs from the specification and says so, with a reason (for example a stricter SAGE profile, or a recorded tension such as T1 to T6). | None; cite where the design says so. |
| `PARSE_VARIANCE` | The texts agree; the parsers split, glossed or linked them differently. | None. |

## Output format

```json
{"unit": "07-did-resolution-contract.md:12.3", "slot": "modality",
 "verdict": "TRANSLATION_DEFECT",
 "spec_evidence": [{"id": "res10#resolving-algorithm.2", "quote": "..."}],
 "explanation": "one or two sentences",
 "fix": {"ko": "full replacement text of the unit, or null", "en": "full replacement text of the unit, or null"}}
```

A fix replaces the whole unit text exactly as it appears in the file (a table
row stays one table row, keeping its pipes), so it can be applied mechanically.
Korean fixes use plain sentences without em dashes.

Rules:

1. Read the specification statement in full, including its `term` (the
   definition-list term it belongs to) and its section. When a parse links a
   statement, check that the link is right before using it.
2. A modal in the design must not be stronger or weaker than the
   specification's for the same subject and condition, unless the design says it
   is a deliberate choice.
3. A recorded tension or design decision counts as deliberate only if the text
   of the unit, or a document it explicitly refers to, states it.
4. When unsure between `PARSE_VARIANCE` and a defect, read both texts again
   aloud in your head; if an implementer could build different behavior from the
   two texts, it is a defect.
