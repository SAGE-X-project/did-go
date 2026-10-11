#!/usr/bin/env python3
"""Extract normative statements from a pinned W3C specification HTML file.

A statement is a sentence that contains an RFC 2119 keyword, or a step of an
algorithm list (`ol.algorithm`), because algorithm steps are normative even
when they carry no keyword. Each statement records its section id and whether
it sits in non-normative context (informative section, note, example, issue).

Usage: extract_spec.py SPEC_KEY HTML_PATH SHA256 > statements.json
The SHA-256 of the file must match, so the output is tied to the pinned bytes.
"""

import hashlib
import html
import json
import re
import sys
from html.parser import HTMLParser

KEYWORDS = re.compile(
    r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|"
    r"RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b"
)
BLOCK_TAGS = {"p", "li", "dd", "dt", "td", "th", "h2", "h3", "h4", "h5", "h6"}
SKIP_TAGS = {"script", "style", "pre"}
INFORMATIVE_CLASSES = {"informative", "note", "example", "issue", "advisement"}
VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "wbr", "col", "source"}
ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "Sec.")


class Frame:
    def __init__(self, tag, attrs, parent):
        classes = set((attrs.get("class") or "").split())
        self.tag = tag
        self.section = attrs.get("id") if tag == "section" else None
        self.informative = bool(classes & INFORMATIVE_CLASSES) or (
            parent.informative if parent else False
        )
        self.algorithm = (tag == "ol" and "algorithm" in classes) or (
            parent.algorithm if parent else False
        )
        self.skip = tag in SKIP_TAGS or (parent.skip if parent else False)
        self.block = tag in BLOCK_TAGS
        self.text = []
        self.uid = None
        self.parent_uid = None


class Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.blocks = []
        self.title = {}
        self.next_uid = 0
        self.last_term = ""

    def section(self):
        for frame in reversed(self.stack):
            if frame.section:
                return frame.section
        return ""

    def block_frame(self):
        for frame in reversed(self.stack):
            if frame.block:
                return frame
        return None

    def handle_starttag(self, tag, attrs):
        if tag in VOID_TAGS:
            return
        parent = self.stack[-1] if self.stack else None
        frame = Frame(tag, dict(attrs), parent)
        if frame.block:
            owner = self.block_frame()
            if owner is not None:
                owner.text.append(" ")
                frame.parent_uid = owner.uid
            self.next_uid += 1
            frame.uid = self.next_uid
        self.stack.append(frame)

    def handle_endtag(self, tag):
        if tag in VOID_TAGS:
            return
        while self.stack:
            frame = self.stack.pop()
            if frame.block:
                self.finish(frame)
            if frame.tag == tag:
                break

    def handle_data(self, data):
        if not self.stack or self.stack[-1].skip:
            return
        owner = self.block_frame()
        if owner is not None:
            owner.text.append(data)

    def finish(self, frame):
        text = " ".join("".join(frame.text).split())
        if not text:
            return
        section = self.section()
        if frame.tag in {"h2", "h3", "h4", "h5", "h6"}:
            self.title.setdefault(section, text)
            return
        if frame.tag == "dt":
            self.last_term = text
        self.blocks.append(
            {
                "term": self.last_term if frame.tag == "dd" else "",
                "uid": frame.uid,
                "parent_uid": frame.parent_uid,
                "section": section,
                "tag": frame.tag,
                "informative": frame.informative,
                "algorithm": frame.algorithm and frame.tag == "li",
                "text": text,
            }
        )


def sentences(text):
    protected = text
    for abbr in ABBREVIATIONS:
        protected = protected.replace(abbr, abbr.replace(".", "․"))
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\"(\[])", protected)
    return [p.replace("․", ".").strip() for p in parts if p.strip()]


def non_normative_sections(blocks):
    marked = set()
    for block in blocks:
        if re.search(r"This section is non-normative", block["text"]):
            marked.add(block["section"])
    return marked


def extract(key, path):
    parser = Extractor()
    with open(path, encoding="utf-8") as handle:
        parser.feed(handle.read())
    marked = non_normative_sections(parser.blocks)
    statements = []
    counters = {}
    first_id = {}
    for block in sorted(parser.blocks, key=lambda b: b["uid"]):
        informative = block["informative"] or block["section"] in marked
        for sentence in sentences(html.unescape(block["text"])):
            found = KEYWORDS.findall(sentence)
            if not found and not block["algorithm"]:
                continue
            section = block["section"]
            counters[section] = counters.get(section, 0) + 1
            sid = f"{key}#{section}.{counters[section]}"
            first_id.setdefault(block["uid"], sid)
            statements.append(
                {
                    "id": sid,
                    "parent": first_id.get(block["parent_uid"]),
                    "spec": key,
                    "section": section,
                    "section_title": parser.title.get(section, ""),
                    "normative": not informative,
                    "algorithm_step": block["algorithm"],
                    "keywords": sorted(set(found)),
                    "term": block["term"],
                    "text": sentence,
                }
            )
    return statements


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    key, path, expected = sys.argv[1:]
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if digest != expected:
        sys.exit(f"{path}: SHA-256 {digest} does not match the pin {expected}")
    json.dump(extract(key, path), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
