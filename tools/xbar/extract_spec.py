#!/usr/bin/env python3
"""Extract normative statements from a pinned W3C specification HTML file.

A statement is a sentence that contains an RFC 2119 keyword, or a step of an
algorithm list (`ol.algorithm`), because algorithm steps are normative even
when they carry no keyword. Each statement records its section id and whether
it sits in non-normative context (informative section, note, example, issue).

ReSpec source files (the community drafts pinned by commit) leave section ids
and the text of local section links to ReSpec. With --respec the extractor
derives the id of a section without one from its heading the way ReSpec does,
fills an empty local link with the title of the section it points to,
closes a list item whose end tag is omitted when the next one starts, and
treats a note or issue nested in an algorithm step as its own informative
block. Without --respec the output for the published W3C specifications is
unchanged.

Usage: extract_spec.py [--respec] SPEC_KEY HTML_PATH SHA256 > statements.json
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


REF_OPEN, REF_CLOSE = "\ue000", "\ue001"
REF = re.compile(REF_OPEN + r"([^" + REF_CLOSE + r"]*)" + REF_CLOSE)


def respec_id(text):
    """Return the id ReSpec derives from a heading for a section without one."""
    slug = re.sub(r"[^\-.0-9a-z_]+", "-", text.strip().lower())
    return re.sub(r"-+", "-", slug).strip("-")


class Frame:
    def __init__(self, tag, attrs, parent, respec=False):
        classes = set((attrs.get("class") or "").split())
        self.tag = tag
        self.is_section = tag == "section"
        self.section = attrs.get("id") if tag == "section" else None
        self.ref = None
        href = attrs.get("href") or ""
        if respec and tag == "a" and href.startswith("#"):
            self.ref = href[1:]
        self.informative = bool(classes & INFORMATIVE_CLASSES) or (
            parent.informative if parent else False
        )
        self.algorithm = (tag == "ol" and "algorithm" in classes) or (
            parent.algorithm if parent else False
        )
        self.skip = tag in SKIP_TAGS or (parent.skip if parent else False)
        # A note or issue inside a list item (ReSpec source) is its own
        # block, so its sentences do not become part of an algorithm step.
        self.block = tag in BLOCK_TAGS or (
            respec and tag == "div" and bool(classes & INFORMATIVE_CLASSES)
            and parent is not None and parent.algorithm
        )
        self.text = []
        self.uid = None
        self.parent_uid = None
        self.ref_owner = None
        self.ref_start = 0


class Extractor(HTMLParser):
    def __init__(self, respec=False):
        super().__init__(convert_charrefs=True)
        self.respec = respec
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
        if self.respec and tag == "li":
            self.close_open_item()
        parent = self.stack[-1] if self.stack else None
        frame = Frame(tag, dict(attrs), parent, self.respec)
        if frame.block:
            owner = self.block_frame()
            if owner is not None:
                owner.text.append(" ")
                frame.parent_uid = owner.uid
            self.next_uid += 1
            frame.uid = self.next_uid
        if frame.ref is not None:
            frame.ref_owner = self.block_frame()
            if frame.ref_owner is not None:
                frame.ref_start = len(frame.ref_owner.text)
        self.stack.append(frame)

    def close_open_item(self):
        """Close an unclosed sibling li, as an HTML parser does (ReSpec source
        omits some </li> end tags)."""
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tag in {"ol", "ul"}:
                return
            if self.stack[i].tag == "li":
                self.handle_endtag("li")
                return

    def handle_endtag(self, tag):
        if tag in VOID_TAGS:
            return
        while self.stack:
            frame = self.stack.pop()
            if frame.ref_owner is not None:
                inner = "".join(frame.ref_owner.text[frame.ref_start:])
                if not inner.strip():
                    # ReSpec fills an empty local link with the section title.
                    frame.ref_owner.text.append(REF_OPEN + frame.ref + REF_CLOSE)
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
        if self.respec and frame.tag in {"h2", "h3", "h4", "h5", "h6"}:
            for owner in reversed(self.stack):
                if owner.is_section:
                    if not owner.section:
                        owner.section = respec_id(text)
                    break
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
                "algorithm": frame.algorithm and frame.tag == "li"
                and not (self.respec and frame.informative),
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


def extract(key, path, respec=False):
    parser = Extractor(respec)
    with open(path, encoding="utf-8") as handle:
        parser.feed(handle.read())
    marked = non_normative_sections(parser.blocks)
    statements = []
    counters = {}
    first_id = {}
    for block in sorted(parser.blocks, key=lambda b: b["uid"]):
        informative = block["informative"] or block["section"] in marked
        text = REF.sub(lambda m: parser.title.get(m.group(1), m.group(1)), block["text"])
        for sentence in sentences(html.unescape(text)):
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
    args = sys.argv[1:]
    respec = bool(args) and args[0] == "--respec"
    if respec:
        args = args[1:]
    if len(args) != 3:
        sys.exit(__doc__)
    key, path, expected = args
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if digest != expected:
        sys.exit(f"{path}: SHA-256 {digest} does not match the pin {expected}")
    json.dump(extract(key, path, respec), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
