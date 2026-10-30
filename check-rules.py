#!/usr/bin/env python3
"""
© TangerangKota-CSIRT (NAuliajati)
Offline check for a PHP2Shell rules file: XML structure, regex compilation,
sample coverage for every rule with testable conditions, and if_sid loss
against the old file.
Usage: python3 check-rules.py [rules.xml] [samples_logs.txt]

Matches are textual. Rule order, if_sid and if_group are not simulated, so
several rules can match one line here while analysisd applies only one.
"""

import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

RULES = sys.argv[1] if len(sys.argv) > 1 else "existing_rules.xml"
SAMPLES = sys.argv[2] if len(sys.argv) > 2 else None
OLD_RULES = "existing_rules_old.xml"

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

    # A rule inserted through a <group> line nests instead of appending, and the
    # file still parses, so check placement explicitly.
    if root.tag != "group":
        raise SystemExit(f"root element is {root.tag}, expected group")
    stray = [r.get("id") for r in rules if r not in list(root)]
    nested = [r.get("id") for r in rules if len(list(r.iter("rule"))) > 1]
    if stray or nested:
        raise SystemExit(f"rules outside the root group: {stray}; nested rules: {nested}")

    for r in rules:
        for node in r:
            if node.tag in ("regex", "match", "field", "url") and (node.text or "").strip():
                try:
                    re.compile(node.text.strip())
                except re.error as exc:
                    raise SystemExit(f"regex {r.get('id')}: {exc}")
                # Wazuh patterns escape slashes; regex101 uses a bare slash as a delimiter.
                if node.get("type") == "pcre2":
                    bare = re.search(r"(?<!\\)/", node.text.strip())
                    if bare:
                        raise SystemExit(f"unescaped slash in {r.get('id')}: {node.text.strip()}")
    return rules


def dropped_parents(rules):
    # The old file can be malformed XML, so read it as text. A rule that carried
    # an if_sid must keep one, because a missing parent disables it at load.
    if not os.path.exists(OLD_RULES):
        return []
    with open(OLD_RULES, encoding="utf-8") as fh:
        text = fh.read()
    cur = {r.get("id"): r for r in rules}
    return sorted(
        rid for rid, body in re.findall(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', text, re.S)
        if re.search(r"<if_sid>", body)
        and (cur.get(rid) is None or cur[rid].find("if_sid") is None)
    )


URL = re.compile(r'"[A-Z]+ (\S+) ')
TESTED = ("match", "regex", "url")


def own_conditions(r):
    # Parent and field conditions need a live manager. decoded_as is checked
    # against the line shape, so a body line cannot be credited to an access-log rule.
    if r.find("field") is not None:
        return []
    conds = [(c.tag, (c.text or "").strip()) for c in r if c.tag in TESTED]
    dec = r.find("decoded_as")
    if dec is not None:
        conds.insert(0, ("decoded_as", (dec.text or "").strip()))
    return conds


def matched(conds, line):
    url = URL.search(line)
    for tag, pattern in conds:
        if tag == "decoded_as":
            if pattern == "web-accesslog" and not url:
                return False
        elif tag == "url":
            if not url or not re.search(pattern, url.group(1)):
                return False
        elif tag == "match":
            if pattern not in line:
                return False
        elif not re.search(pattern, line):
            return False
    return True


def main():
    rules = load()
    lost = dropped_parents(rules)
    if lost:
        raise SystemExit(f"rules that lost an if_sid their old file had: {lost}")
    tested_rules = [(r.get("id"), own_conditions(r)) for r in rules if own_conditions(r)]
    files = [SAMPLES] if SAMPLES else sorted(glob.glob("logtest-samples-*.txt"))
    samples = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            samples.extend((f, line.strip()) for line in fh if line.strip())

    covered = set()
    for name, line in samples:
        hits = [rid for rid, conds in tested_rules if matched(conds, line)]
        covered.update(hits)
        label = "nginx" if "nginx" in name else "apache"
        print(f"{label:>6} {','.join(hits) or '--':>16}  {line[:88]}")

    missing = [rid for rid, conds in tested_rules if rid not in covered]
    if missing:
        raise SystemExit(f"\nrules whose conditions no sample reaches: {missing}")
    print(f"\n{len(files)} sample files, {len(samples)} lines, {len(rules)} rules, "
          f"{len(tested_rules)} with testable conditions, all reachable")


if __name__ == "__main__":
    main()
