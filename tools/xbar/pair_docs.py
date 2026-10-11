#!/usr/bin/env python3
"""Split a Korean design document and its English translation into units and pair them.

A unit is a heading, a table row, a list item, a paragraph or a fenced code
block. Units are paired by position inside each heading section. A section
whose unit counts differ between the two files is reported as misaligned,
because that means something was added or dropped in translation.

Usage: pair_docs.py KO_DIR EN_DIR FILE [FILE ...] > units.json
"""

import json
import re
import sys

SEPARATOR_ROW = re.compile(r"^\|\s*:?-{3,}")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")


def units(path):
    out = []
    section = 0
    heading = ""
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.append((section, heading, "code", "\n".join(lines[i : j + 1])))
            i = j + 1
            continue
        if re.match(r"^#{1,6} ", line):
            section += 1
            heading = line.lstrip("#").strip()
            out.append((section, heading, "heading", heading))
        elif line.startswith("|"):
            if not SEPARATOR_ROW.match(line):
                out.append((section, heading, "row", line.strip()))
        elif LIST_ITEM.match(line):
            text = [line.strip()]
            while i + 1 < len(lines) and lines[i + 1].startswith("  ") and not LIST_ITEM.match(lines[i + 1]):
                i += 1
                text.append(lines[i].strip())
            out.append((section, heading, "item", " ".join(text)))
        elif line.strip() and line.strip() != "---":
            text = [line.strip()]
            while (
                i + 1 < len(lines)
                and lines[i + 1].strip()
                and not re.match(r"^(#{1,6} |\||```|---)", lines[i + 1])
                and not LIST_ITEM.match(lines[i + 1])
            ):
                i += 1
                text.append(lines[i].strip())
            out.append((section, heading, "para", " ".join(text)))
        i += 1
    return out


def pair(name, ko_dir, en_dir):
    ko = units(f"{ko_dir}/{name}")
    en = units(f"{en_dir}/{name}")
    sections = sorted({u[0] for u in ko} | {u[0] for u in en})
    pairs, misaligned = [], []
    for s in sections:
        k = [u for u in ko if u[0] == s]
        e = [u for u in en if u[0] == s]
        kinds_k = [u[2] for u in k]
        kinds_e = [u[2] for u in e]
        if kinds_k != kinds_e:
            misaligned.append(
                {
                    "file": name,
                    "section": s,
                    "ko_heading": k[0][1] if k else None,
                    "en_heading": e[0][1] if e else None,
                    "ko_kinds": kinds_k,
                    "en_kinds": kinds_e,
                }
            )
            continue
        for n, (ku, eu) in enumerate(zip(k, e)):
            pairs.append(
                {
                    "id": f"{name}:{s}.{n}",
                    "file": name,
                    "section": s,
                    "en_heading": eu[1],
                    "kind": ku[2],
                    "ko": ku[3],
                    "en": eu[3],
                }
            )
    return pairs, misaligned


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    ko_dir, en_dir, names = sys.argv[1], sys.argv[2], sys.argv[3:]
    result = {"pairs": [], "misaligned": []}
    for name in names:
        p, m = pair(name, ko_dir, en_dir)
        result["pairs"].extend(p)
        result["misaligned"].extend(m)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
