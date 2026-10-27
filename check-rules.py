#!/usr/bin/env python3
"""
© TangerangKota-CSIRT (NAuliajati)
Offline check for php2shell_rules.xml: XML structure, regex compilation, and sample coverage for the text-only rules.
Usage: python3 check-rules.py [rules.xml] [samples_logs.txt]
"""

import re
import sys
import xml.etree.ElementTree as ET

RULES = sys.argv[1] if len(sys.argv) > 1 else "php2shell_rules.xml"
SAMPLES = sys.argv[2] if len(sys.argv) > 2 else "logtest-samples.txt"

# Decoder and correlation rules need a live manager, so the checker leaves them to wazuh-logtest.
COND = {
    "if_sid", "if_matched_sid", "if_group", "if_matched_group", "decoded_as",
    "same_srcip", "same_field", "srcip", "field", "frequency", "url",
}


def load():
    root = ET.parse(RULES).getroot()
    rules = list(root.iter("rule"))
    ids = [r.get("id") for r in rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    bad_level = [r.get("id") for r in rules if not 1 <= int(r.get("level")) <= 16]
    bad_mitre = [
        m.text for r in rules for m in r.iter("id")
        if m.text and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", m.text)
    ]
    if dupes or bad_level or bad_mitre:
        raise SystemExit(f"dupes={dupes} bad_level={bad_level} bad_mitre={bad_mitre}")

    for r in rules:
        for node in r:
            if node.tag in ("regex", "match", "field", "url") and (node.text or "").strip():
                try:
                    re.compile(node.text.strip())
                except re.error as exc:
                    raise SystemExit(f"regex {r.get('id')}: {exc}")
                # regex101 treats a bare slash as a delimiter
                if node.get("type") == "pcre2":
                    bare = re.search(r"(?<!\\)/", node.text.strip())
                    if bare:
                        raise SystemExit(f"unescaped slash in {r.get('id')}: {node.text.strip()}")
    return rules


def main():
    rules = load()
    text_rules = [
        (r.get("id"), [(c.tag, c.text.strip()) for c in r if c.tag in ("match", "regex")])
        for r in rules if not ({c.tag for c in r} & COND)
    ]
    samples = [l.strip() for l in open(SAMPLES, encoding="utf-8") if l.strip()]

    covered = set()
    for line in samples:
        hits = [rid for rid, conds in text_rules if all(re.search(p, line) for _, p in conds)]
        covered.update(hits)
        print(f"{','.join(hits) or '--':>16}  {line[:96]}")

    missing = [rid for rid, _ in text_rules if rid not in covered]
    if missing:
        raise SystemExit(f"\nrules with no sample: {missing}")
    print(f"\n{len(rules)} rules, {len(text_rules)} text-only, all reachable")


if __name__ == "__main__":
    main()
