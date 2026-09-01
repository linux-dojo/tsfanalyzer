#!/usr/bin/env python3
"""Find top-level identifiers declared twice in the same Go package.

There is no Go compiler in this environment, so a redeclaration reaches the
user's docker build as a bare "exit code: 1". That is exactly what happened
with stripLogPrefix: gphip.go already had one, search.go got a second with a
different signature, and every local check passed because braces balanced and
imports were used.

This walks each package directory, collects top-level func/type/var/const
names, and reports any name declared more than once. Methods are keyed by
receiver type so that two types may each have a Present() without a clash.
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "backend"

FUNC = re.compile(r"^func\s+(?:\((?P<recv>[^)]*)\)\s*)?(?P<name>[A-Za-z_]\w*)\s*[\(\[]")
TYPE = re.compile(r"^type\s+(?P<name>[A-Za-z_]\w*)\b")
DECL = re.compile(r"^(?:var|const)\s+(?P<name>[A-Za-z_]\w*)\b")
# var ( ... ) / const ( ... ) blocks
GROUP_OPEN = re.compile(r"^(var|const|type)\s*\($")
# The name must end at a word boundary. An earlier version allowed a trailing
# letter as a delimiter, so "opLT" backtracked to "opL" + "T" and collided
# with "opLE" — a checker that invents its own false positives is worse than
# none, because the real hit gets lost in the noise.
GROUP_ITEM = re.compile(r"^\t(?P<name>[A-Za-z_]\w*)(?=\s|,|=|\[|\*|$)")


def recv_type(recv: str) -> str:
    """Reduce "e GPEnforcer" or "c *GPGatewayConfig" to the bare type name."""
    parts = recv.replace("*", "").split()
    return parts[-1] if parts else ""


def scan(path: Path):
    """Yield (key, line_no) for each top-level declaration in one file."""
    in_group = None
    depth = 0
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("//"):
            continue

        if in_group:
            if line == ")":
                in_group = None
                continue
            if depth == 0:
                m = GROUP_ITEM.match(line)
                if m:
                    yield m.group("name"), n
            depth += line.count("{") - line.count("}")
            depth = max(depth, 0)
            continue

        if GROUP_OPEN.match(line):
            in_group, depth = GROUP_OPEN.match(line).group(1), 0
            continue

        m = FUNC.match(line)
        if m:
            name = m.group("name")
            recv = m.group("recv")
            yield (f"{recv_type(recv)}.{name}" if recv else name), n
            continue
        for pat in (TYPE, DECL):
            m = pat.match(line)
            if m:
                yield m.group("name"), n
                break


def main() -> int:
    problems = 0
    pkgs = defaultdict(lambda: defaultdict(list))
    for f in sorted(ROOT.rglob("*.go")):
        for name, line in scan(f):
            if name == "_" or name == "init":
                continue
            pkgs[f.parent][name].append((f.name, line))

    for pkg, names in sorted(pkgs.items()):
        for name, sites in sorted(names.items()):
            if len(sites) > 1:
                problems += 1
                where = ", ".join(f"{f}:{l}" for f, l in sites)
                print(f"{pkg.relative_to(ROOT)}: {name!r} declared {len(sites)} times -> {where}")

    print("no duplicate declarations" if not problems
          else f"\n{problems} duplicate declaration(s) — this is a compile error")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
