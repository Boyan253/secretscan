#!/usr/bin/env python3
"""Scan a tree for things that look like committed credentials."""

import argparse
import math
import os
import re
import sys

RULES = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe key", re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("assigned secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".mypy_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".exe", ".dll",
            ".so", ".mp4", ".mp3", ".woff", ".woff2", ".ico", ".lock"}


def entropy(text):
    """Shannon entropy in bits per character -- random strings score high."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(text, keep=4):
    text = text.strip()
    if len(text) <= keep * 2:
        return "*" * len(text)
    return "%s%s%s" % (text[:keep], "*" * (len(text) - keep * 2), text[-keep:])


def scan_text(text, min_entropy=0.0):
    """Yield (rule_name, line_number, matched_text)."""
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        for name, pattern in RULES:
            match = pattern.search(line)
            if not match:
                continue
            found = match.group(0)
            if min_entropy and entropy(found) < min_entropy:
                continue
            yield (name, lineno, found)


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
            except OSError:
                continue
            yield path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--min-entropy", type=float, default=0.0,
                    help="drop matches below this bits-per-char score")
    ap.add_argument("--show", action="store_true", help="print the secret unredacted")
    args = ap.parse_args(argv)

    hits = 0
    for path in walk_files(os.path.abspath(args.path)):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for name, lineno, found in scan_text(text, args.min_entropy):
            hits += 1
            shown = found if args.show else redact(found)
            print("%s:%d  %s  %s" % (os.path.relpath(path, args.path), lineno, name, shown))
    print("\n%d possible secret(s)" % hits, file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
