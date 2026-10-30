#!/usr/bin/env python3
"""Publication check for this public repository: nothing private gets added.

Scans what a change would publish (the lines a commit range adds, its commit
messages and author/committer identities, a branch name, PR text files) or, with --tree, every tracked file.
Built-in rules are generic: private IPv4 ranges and user home-directory paths.
Operator-specific terms (hostnames, private repository names, tracker issue
keys) belong in a private denylist that is never committed: one Python regex
per line, `#` comments, read from --denylist or $FACTORY_PRIVACY_DENYLIST
(default ~/.config/factory/privacy-denylist). Findings name the rule and the
location and mask the match, so a CI log never repeats a protected term.

    scripts/privacy-check.py --range origin/main...HEAD --branch "$(git branch --show-current)"
    scripts/privacy-check.py --text pr-body.md
    scripts/privacy-check.py --tree        # report existing exposure
    scripts/privacy-check.py --range origin/main...HEAD --require-denylist   # gate check
    scripts/privacy-check.py --range origin/main...HEAD --published upstream/main   # skip upstream's own text

Exit 0: clean; 1: findings; 2: usage or git error, or a required denylist missing or empty.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

BUILTIN = {
    "private IPv4 address": r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b",
    "user home path": r"(?:/home|/Users)/(?!runner\b|user\b|example\b|<)[A-Za-z0-9._-]+",
}
DEFAULT_DENYLIST = Path("~/.config/factory/privacy-denylist")


def fail(message: str) -> None:
    print(f"privacy-check: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_rules(denylist: Path | None, required: bool = False) -> list[tuple[str, re.Pattern[str]]]:
    rules = [(label, re.compile(pattern)) for label, pattern in BUILTIN.items()]
    path = denylist or Path(os.environ.get("FACTORY_PRIVACY_DENYLIST") or DEFAULT_DENYLIST).expanduser()
    if (denylist or required) and not path.is_file():
        fail(f"denylist {path} not found")
    if path.is_file():
        for number, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append((f"denylist rule {number}", re.compile(line, re.IGNORECASE)))
    if required and len(rules) == len(BUILTIN):
        fail(f"denylist {path} has no rules")
    return rules


def mask(text: str, spans: list[tuple[int, int]]) -> str:
    """`text` with every span starred out, so a finding never echoes any protected term."""
    chars = list(text)
    for start, end in spans:
        chars[start:end] = "*" * (end - start)
    return "".join(chars).strip()[:160]


def scan(source: str, lines, rules) -> list[str]:
    """Findings for `lines`: strings, or (line number, text) pairs."""
    found = []
    for number, line in (lines if lines and isinstance(lines[0], tuple) else enumerate(lines, 1)):
        hits = [(label, m.span()) for label, rule in rules for m in rule.finditer(line)]
        masked = mask(line, [span for _, span in hits])
        for label in dict.fromkeys(label for label, _ in hits):
            found.append(f"{source}:{number}: {label}: {masked}")
    return found


def git(*args: str) -> str:
    # Diffs and messages can carry non-UTF-8 bytes (binary-ish files, legacy encodings);
    # decode leniently so one such commit never aborts the scan of the whole range.
    proc = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", check=False)
    if proc.returncode:
        fail(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def added_lines(rng: str) -> dict[str, list[tuple[int, str]]]:
    """{path: [(new line number, text)]} for every line the range adds."""
    out: dict[str, list[tuple[int, str]]] = {}
    path, n = "", 0
    for line in git("diff", "--text", "--no-ext-diff", "--no-textconv", "--unified=0", "--no-prefix", rng).splitlines():
        if line.startswith("+++ "):
            path = line[4:]
        elif line.startswith("@@ "):
            n = int(re.match(r"@@ -\S+ \+(\d+)", line).group(1))
        elif line.startswith("+") and path != "/dev/null":
            out.setdefault(path, []).append((n, line[1:]))
            n += 1
    return out


def resolve(ref: str) -> str | None:
    """`ref`'s commit, or None when it does not resolve (then nothing counts as published)."""
    proc = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                          capture_output=True, text=True, check=False)
    return proc.stdout.strip() or None


def published_lines(commit: str, path: str) -> set[str]:
    """The lines of `path` at an already-public `commit` (empty when the file is absent there)."""
    proc = subprocess.run(["git", "show", f"{commit}:{path}"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False)
    return set(proc.stdout.splitlines()) if proc.returncode == 0 else set()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--range", help="commit range whose added lines, messages and author/committer identities are checked, e.g. origin/main...HEAD")
    parser.add_argument("--branch", help="branch name to check")
    parser.add_argument("--text", nargs="*", default=[], help="text files to check (PR title/body drafts)")
    parser.add_argument("--tree", action="store_true", help="check every tracked file (existing exposure)")
    parser.add_argument("--denylist", type=Path, help="private denylist (one regex per line)")
    parser.add_argument("--published", action="append", default=[], metavar="REF",
                        help="already-public revision, e.g. upstream/main (repeatable): a --range line equal to a "
                             "line of the same file there, or a message or identity of a commit it contains, is not new "
                             "exposure; a REF that does not resolve excludes nothing")
    parser.add_argument("--require-denylist", action="store_true",
                        help="fail (exit 2) unless the default or $FACTORY_PRIVACY_DENYLIST denylist exists and has "
                             "a rule; for a gate check, where a missing file must not pass on the generic rules alone")
    args = parser.parse_args(argv)
    if not (args.range or args.branch or args.text or args.tree):
        parser.error("nothing to check")
    rules = load_rules(args.denylist, args.require_denylist)
    found = []
    if args.range:
        published = [commit for ref in args.published if (commit := resolve(ref))]
        for path, rows in added_lines(args.range).items():
            public = set().union(*(published_lines(commit, path) for commit in published))
            found += scan(path, [row for row in rows if row[1] not in public], rules)
        for sha in git("rev-list", args.range.replace("...", ".."), *(f"^{c}" for c in published)).split():
            found += scan(f"commit {sha[:12]} message", git("log", "-1", "--format=%B", sha).splitlines(), rules)
            author, committer = git("log", "-1", "--format=%an <%ae>%n%cn <%ce>", sha).rstrip("\n").split("\n")
            found += scan(f"commit {sha[:12]} author", [author], rules)
            found += scan(f"commit {sha[:12]} committer", [committer], rules)
    if args.branch:
        found += scan("branch name", [args.branch], rules)
    for name in args.text:
        found += scan(name, Path(name).read_text(errors="replace").splitlines(), rules)
    if args.tree:
        for path in git("ls-files", "-z").split("\0"):
            if path and Path(path).is_file() and not Path(path).is_symlink():
                found += scan(path, Path(path).read_text(errors="replace").splitlines(), rules)
    for line in found:
        print(line)
    print(f"privacy-check: {len(found)} finding(s)" if found else "privacy-check: clean")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
