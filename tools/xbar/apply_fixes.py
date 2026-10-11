#!/usr/bin/env python3
"""Apply the fixes recorded in adjudication verdicts to the Korean and English documents.

A fix replaces a whole unit. The unit's current text is taken from units.json
and must occur exactly once in the file; otherwise the fix is reported and
skipped, so nothing is replaced by guess. Units that pair_docs.py joined from
several lines are matched line by line.

Usage: apply_fixes.py UNITS_JSON KO_DIR EN_DIR VERDICT_JSON [VERDICT_JSON ...]
"""

import json
import re
import sys


def locate(content, unit_text):
    if content.count(unit_text) == 1:
        return unit_text
    words = unit_text.split()
    pattern = r"[ \t]*" + r"\s+".join(re.escape(w) for w in words)
    matches = list(re.finditer(pattern, content))
    if len(matches) == 1:
        return matches[0].group(0)
    return None


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    units_path, ko_dir, en_dir, verdict_paths = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    with open(units_path, encoding="utf-8") as handle:
        units = {p["id"]: p for p in json.load(handle)["pairs"]}
    applied, skipped = 0, []
    for path in verdict_paths:
        with open(path, encoding="utf-8") as handle:
            verdicts = json.load(handle)
        for verdict in verdicts:
            fix = verdict.get("fix") or {}
            unit = units.get(verdict.get("unit"))
            if unit is None:
                continue
            for lang, directory in (("ko", ko_dir), ("en", en_dir)):
                new = fix.get(lang)
                if not new:
                    continue
                target = f"{directory}/{unit['file']}"
                with open(target, encoding="utf-8") as handle:
                    content = handle.read()
                found = locate(content, unit[lang])
                if found is None:
                    if new in content:
                        continue
                    skipped.append(f"{verdict['unit']} {lang}: unit text not found exactly once")
                    continue
                content = content.replace(found, new, 1)
                with open(target, "w", encoding="utf-8") as handle:
                    handle.write(content)
                applied += 1
    print(f"applied={applied} skipped={len(skipped)}")
    for line in skipped:
        print("SKIPPED", line)


if __name__ == "__main__":
    main()
