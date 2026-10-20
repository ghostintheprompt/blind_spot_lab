#!/usr/bin/env python3
"""
naive_regex_review.py — the baseline the AST auditor is meant to beat.

A plausible string-matching reviewer: flag a shell sink only when it sees
obvious string concatenation feeding it, flag `verify=False`, flag `md5`.
It is fast and it is blind. It cannot see a command built in an f-string,
it cannot reason about whether an OAuth 'state' was validated, and it
cannot tell a constant shell call from an injectable one.

Kept in the repo precisely so the gap is reproducible, not asserted.
Run:  python3 naive_regex_review.py fixtures/command_injection.py
"""
import re
import sys

PATTERNS = [
    ("REGEX-CMD", r"(os\.system|os\.popen|subprocess\.\w+)\([^)]*[\"'][^)]*\+", "possible command injection"),
    ("REGEX-TLS", r"verify\s*=\s*False", "TLS verification disabled"),
    ("REGEX-MD5", r"\bmd5\b", "weak hash"),
]


def review(source: str):
    hits = []
    for i, line in enumerate(source.splitlines(), 1):
        for rule, pat, msg in PATTERNS:
            if re.search(pat, line):
                hits.append({"rule_id": rule, "line": i, "msg": msg})
    return hits


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: naive_regex_review.py <file.py>", file=sys.stderr)
        raise SystemExit(2)
    with open(sys.argv[1], encoding="utf-8") as fh:
        found = review(fh.read())
    verdict = "REJECT" if found else "PASS"
    print(verdict)
    for h in found:
        print(f"  L{h['line']:<4} {h['rule_id']}  {h['msg']}")
