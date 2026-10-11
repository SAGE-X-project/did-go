#!/usr/bin/env python3
"""Compare X-bar parses of the specifications, the Korean design and the English design.

Inputs (a work directory produced by the other tools and the parsers):
  units.json                 Korean/English unit pairs from pair_docs.py
  {core10,did11,cid10,res10}.json   statements from extract_spec.py
  parses/ko/*.json, parses/en/*.json, parses/spec/*.json   parser output (SCHEMA.md)

Outputs, written to OUT_DIR:
  graph.json      nodes (spec statements, Korean units, English units, claims) and
                  edges (translates, restates, has-claim)
  findings.json   every slot difference, classed HARD or SOFT
  coverage.json   normative spec statements that no design unit links to
  findings.md     findings with a Mermaid tree for each HARD one

HARD differences change meaning for an implementer: modality, polarity, quantifier,
claim count, condition count, verb, head nouns, spec links, code outside comments.
SOFT differences are gloss wording that may be paraphrase; a reviewer decides.

Usage: compare.py WORK_DIR OUT_DIR
"""

import glob
import json
import os
import re
import sys

SPECS = ("core10", "did11", "cid10", "res10")
STOP = {"a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "be", "with", "by", "as", "that", "its"}


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def norm(text):
    text = (text or "").lower()
    text = re.sub(r"[`*_\"'()\[\],.;:]", " ", text)
    words = [w[:-1] if w.endswith("s") and len(w) > 3 else w for w in text.split()]
    return " ".join(w for w in words if w not in STOP)


def overlap(a, b):
    sa, sb = set(norm(a).split()), set(norm(b).split())
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / max(1, len(sa | sb))


def parses(work, lang):
    out = {}
    for path in sorted(glob.glob(os.path.join(work, "parses", lang, "*.json"))):
        for item in load(path):
            out[item["id"]] = item
    return out


def strip_comments(code):
    lines = []
    for line in code.split("\n"):
        line = re.sub(r"//.*$", "", line)
        line = re.sub(r"#.*$", "", line) if line.lstrip().startswith("#") else line
        line = re.sub(r"%%.*$", "", line)
        lines.append(line.rstrip())
    return "\n".join(l for l in lines if l.strip())


TECH = re.compile(r"[A-Za-z_][A-Za-z0-9_./#:+-]*|\d+")


def technical(line):
    """Tokens that translation must not change: identifiers, codes, numbers."""
    out = []
    for tok in TECH.findall(line):
        tok = tok.rstrip(".:,")
        if not tok:
            continue
        if tok.isdigit() or "_" in tok or any(c in tok for c in "./#") or any(c.isdigit() for c in tok) \
                or (len(tok) > 1 and tok.isupper()) or any(c.isupper() for c in tok[1:]):
            out.append(tok)
    return out


def code_skeleton(code):
    lines = code.split("\n")
    mermaid = lines[0].strip() == "```mermaid"
    result = []
    for line in lines:
        line = re.sub(r"//.*$", "", line)
        line = re.sub(r"#\s.*$", "", line)
        line = re.sub(r"/\*.*?\*/", "", line)
        if mermaid:
            line = re.sub(r"%%.*$", "", line)
            line = re.sub(r"\[[^\]]*\]|\([^)]*\)|\{[^}]*\}|\|[^|]*\||\"[^\"]*\"", "", line)
            line = re.sub(r":.*$", "", line) if re.search(r"(->>|-->>|->|-x|--x|Note )", line) else line
            line = re.sub(r"^\s*(subgraph|Note|title|participant|actor)\b.*$", lambda m: m.group(1), line)
        result.append(technical(line))
    return [t for t in result if t]


def quoted_identifiers(text):
    return sorted(set(re.findall(r"`([^`]+)`", text)))


def slots(claim):
    t = claim.get("t") or {}
    spec = claim.get("spec") or {}
    comp = claim.get("comp") or {}
    return {
        "modality": t.get("modality"),
        "neg": bool(t.get("neg")),
        "spec_q": spec.get("q"),
        "spec_head": norm(spec.get("head")),
        "verb": norm(claim.get("v")),
        "comp_q": comp.get("q"),
        "comp_head": norm(comp.get("head")),
        "comp_value": (comp.get("value") or "").strip().lower(),
        "cp_count": len(claim.get("cp") or []),
        "adj_roles": sorted(a.get("role", "") for a in claim.get("adj") or []),
        "links": sorted(set(claim.get("spec_links") or [])),
    }


HARD_SLOTS = ("modality", "neg", "cp_count")
SOFT_SLOTS = ("spec_q", "comp_q", "links")
WORD_SLOTS = ("spec_head", "verb", "comp_head", "comp_value")


def strengths(claims):
    """Multiset of (modality, negation) over a unit's claims, ignoring DECL."""
    out = {}
    for claim in claims:
        s = slots(claim)
        if s["modality"] in (None, "DECL"):
            continue
        key = (s["modality"], s["neg"])
        out[key] = out.get(key, 0) + 1
    return out


def compare_claims(unit_id, ko_claims, en_claims, findings):
    ks_all, es_all = strengths(ko_claims), strengths(en_claims)
    if set(ks_all) != set(es_all):
        findings.append({"unit": unit_id, "class": "HARD", "slot": "strength_set",
                         "ko": sorted(map(list, ks_all)), "en": sorted(map(list, es_all))})
    if len(ko_claims) != len(en_claims):
        findings.append({"unit": unit_id, "class": "SOFT", "slot": "claim_count",
                         "ko": len(ko_claims), "en": len(en_claims)})
        return
    for n, (kc, ec) in enumerate(zip(ko_claims, en_claims)):
        ks, es = slots(kc), slots(ec)
        for slot in HARD_SLOTS:
            if ks[slot] != es[slot]:
                findings.append({"unit": unit_id, "claim": n, "class": "HARD", "slot": slot,
                                 "ko": ks[slot], "en": es[slot]})
        for slot in SOFT_SLOTS:
            if ks[slot] != es[slot]:
                findings.append({"unit": unit_id, "claim": n, "class": "SOFT", "slot": slot,
                                 "ko": ks[slot], "en": es[slot]})
        for slot in WORD_SLOTS:
            if ks[slot] != es[slot] and overlap(ks[slot], es[slot]) < 0.5:
                findings.append({"unit": unit_id, "claim": n, "class": "SOFT",
                                 "slot": slot, "ko": ks[slot], "en": es[slot]})
        if ks["adj_roles"] != es["adj_roles"]:
            findings.append({"unit": unit_id, "claim": n, "class": "SOFT", "slot": "adj_roles",
                             "ko": ks["adj_roles"], "en": es["adj_roles"]})


def compare_with_spec(unit_id, lang, claims, spec_parse, findings):
    for n, claim in enumerate(claims):
        mine = slots(claim)
        for link in mine["links"]:
            target = spec_parse.get(link)
            if target is None:
                findings.append({"unit": unit_id, "claim": n, "class": "HARD", "slot": "unknown_link",
                                 "lang": lang, "link": link})
                continue
            spec_claims = target.get("claims") or []
            if not spec_claims:
                continue
            best = max(spec_claims, key=lambda c: overlap(slots(c)["comp_head"] + " " + slots(c)["verb"],
                                                           mine["comp_head"] + " " + mine["verb"]))
            theirs = slots(best)
            if mine["modality"] != "DECL" and theirs["modality"] != "DECL":
                if (mine["modality"], mine["neg"]) != (theirs["modality"], theirs["neg"]):
                    findings.append({"unit": unit_id, "claim": n, "class": "HARD", "slot": "spec_modality",
                                     "lang": lang, "link": link,
                                     "doc": [mine["modality"], mine["neg"]],
                                     "spec": [theirs["modality"], theirs["neg"]]})
            if mine["neg"] != theirs["neg"] and "DECL" in (mine["modality"], theirs["modality"]):
                findings.append({"unit": unit_id, "claim": n, "class": "SOFT", "slot": "spec_polarity",
                                 "lang": lang, "link": link})


def mermaid(claim, label):
    s = slots(claim)
    t = claim.get("t") or {}
    lines = [f"  subgraph {label}"]
    node = label.replace("-", "_")
    lines.append(f'    {node}_CP["CP: {len(claim.get("cp") or [])} condition(s)"] --> {node}_TP["TP"]')
    lines.append(f'    {node}_TP --> {node}_S["Spec: {s["spec_q"]} {s["spec_head"]}"]')
    lines.append(f'    {node}_TP --> {node}_T["T: {t.get("modality")}{" NOT" if t.get("neg") else ""}"]')
    lines.append(f'    {node}_TP --> {node}_VP["VP: {s["verb"]}"]')
    lines.append(f'    {node}_VP --> {node}_C["Comp: {s["comp_q"]} {s["comp_head"]}"]')
    lines.append("  end")
    return "\n".join(lines).replace('"', "'").replace("['", '["').replace("']", '"]')


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    work, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    units = load(os.path.join(work, "units.json"))
    ko, en = parses(work, "ko"), parses(work, "en")
    spec_parse = parses(work, "spec")
    statements = {}
    for key in SPECS:
        for s in load(os.path.join(work, f"{key}.json")):
            statements[s["id"]] = s

    nodes, edges, findings = [], [], []
    linked = set()
    for pair in units["pairs"]:
        uid = pair["id"]
        nodes.append({"id": f"ko:{uid}", "type": "ko-unit", "text": pair["ko"]})
        nodes.append({"id": f"en:{uid}", "type": "en-unit", "text": pair["en"]})
        edges.append({"from": f"ko:{uid}", "to": f"en:{uid}", "type": "translates"})
        if pair["kind"] == "code":
            ks, es = code_skeleton(pair["ko"]), code_skeleton(pair["en"])
            if ks != es:
                findings.append({"unit": uid, "class": "HARD", "slot": "code",
                                 "ko_only": sorted({t for l in ks for t in l} - {t for l in es for t in l}),
                                 "en_only": sorted({t for l in es for t in l} - {t for l in ks for t in l}),
                                 "lines": [len(ks), len(es)]})
            if re.search(r"[\uac00-\ud7a3]", pair["ko"]):
                findings.append({"unit": uid, "class": "SOFT", "slot": "code_prose"})
            continue
        if quoted_identifiers(pair["ko"]) != quoted_identifiers(pair["en"]):
            missing = sorted(set(quoted_identifiers(pair["ko"])) ^ set(quoted_identifiers(pair["en"])))
            findings.append({"unit": uid, "class": "SOFT", "slot": "identifiers", "diff": missing})
        if pair["kind"] == "heading":
            continue
        kp, ep = ko.get(uid), en.get(uid)
        if kp is None or ep is None:
            findings.append({"unit": uid, "class": "HARD", "slot": "missing_parse",
                             "ko": kp is not None, "en": ep is not None})
            continue
        if bool(kp.get("normative")) != bool(ep.get("normative")):
            findings.append({"unit": uid, "class": "HARD", "slot": "normative",
                             "ko": kp.get("normative"), "en": ep.get("normative")})
        kc, ec = kp.get("claims") or [], ep.get("claims") or []
        compare_claims(uid, kc, ec, findings)
        for lang, claims in (("ko", kc), ("en", ec)):
            compare_with_spec(uid, lang, claims, spec_parse, findings)
            for n, claim in enumerate(claims):
                cid = f"{lang}:{uid}#c{n}"
                nodes.append({"id": cid, "type": "claim", "slots": slots(claim)})
                edges.append({"from": f"{lang}:{uid}", "to": cid, "type": "has-claim"})
                for link in claim.get("spec_links") or []:
                    linked.add(link)
                    edges.append({"from": cid, "to": f"spec:{link}", "type": "restates"})
    for sid, s in statements.items():
        nodes.append({"id": f"spec:{sid}", "type": "spec-statement", "normative": s["normative"],
                      "text": s["text"]})
        for n, claim in enumerate((spec_parse.get(sid) or {}).get("claims") or []):
            cid = f"spec:{sid}#c{n}"
            nodes.append({"id": cid, "type": "claim", "slots": slots(claim)})
            edges.append({"from": f"spec:{sid}", "to": cid, "type": "has-claim"})

    coverage = [
        {"id": sid, "section": s["section"], "text": s["text"]}
        for sid, s in statements.items()
        if s["normative"] and sid not in linked
    ]
    with open(os.path.join(out, "graph.json"), "w", encoding="utf-8") as h:
        json.dump({"nodes": nodes, "edges": edges}, h, ensure_ascii=False, indent=1)
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as h:
        json.dump(findings, h, ensure_ascii=False, indent=1)
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as h:
        json.dump(coverage, h, ensure_ascii=False, indent=1)

    hard = [f for f in findings if f["class"] == "HARD"]
    soft = [f for f in findings if f["class"] == "SOFT"]
    md = ["# X-bar comparison findings", "",
          f"Units: {len(units['pairs'])}. Spec statements: {len(statements)}. "
          f"HARD: {len(hard)}. SOFT: {len(soft)}. Unlinked normative spec statements: {len(coverage)}.", ""]
    for f in hard:
        md.append(f"## {f['unit']} ({f['slot']})")
        md.append("")
        md.append("```json")
        md.append(json.dumps(f, ensure_ascii=False))
        md.append("```")
        uid = f["unit"]
        claim_index = f.get("claim")
        if claim_index is not None and uid in ko and uid in en:
            kc = (ko[uid].get("claims") or [])
            ec = (en[uid].get("claims") or [])
            if claim_index < len(kc) and claim_index < len(ec):
                md.append("")
                md.append("```mermaid")
                md.append("flowchart TB")
                md.append(mermaid(kc[claim_index], "KO"))
                md.append(mermaid(ec[claim_index], "EN"))
                md.append("```")
        md.append("")
    with open(os.path.join(out, "findings.md"), "w", encoding="utf-8") as h:
        h.write("\n".join(md) + "\n")
    print(f"units={len(units['pairs'])} statements={len(statements)} hard={len(hard)} "
          f"soft={len(soft)} unlinked={len(coverage)}")


if __name__ == "__main__":
    main()
