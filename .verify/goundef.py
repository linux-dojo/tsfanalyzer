#!/usr/bin/env python3
"""Find package-level identifiers that are used but never declared.

This is the check that was missing. Twice now a build has failed on something
none of the other harnesses can see:

  * stripLogPrefix declared in two files  -> caught by godupes.py
  * gpEnforcerEmptyRe used after an edit removed its declaration -> caught here

Both were introduced by editing a file with a scripted slice replacement, which
is exactly the operation that silently drops a neighbouring declaration.

The approach is deliberately conservative. It collects every package-level
declaration in a package (plus imported package names, local variables,
parameters, struct fields and Go's predeclared identifiers), then reports uses
of a lowercase project-looking identifier that matches nothing. Anything it is
unsure about it stays quiet on, because a checker that cries wolf gets ignored
-- the point is to catch the "undefined: X" class, not to reimplement a
compiler.
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "backend"

PREDECLARED = {
    "append", "cap", "close", "complex", "copy", "delete", "imag", "len",
    "make", "new", "panic", "print", "println", "real", "recover", "clear",
    "min", "max", "bool", "byte", "complex64", "complex128", "error", "float32",
    "float64", "int", "int8", "int16", "int32", "int64", "rune", "string",
    "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any", "comparable",
    "true", "false", "iota", "nil", "_",
}

DECL_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)")
DECL_TYPE = re.compile(r"^type\s+([A-Za-z_]\w*)")
DECL_VAR = re.compile(r"^(?:var|const)\s+([A-Za-z_]\w*)")
GROUP_OPEN = re.compile(r"^(var|const|type)\s*\($")
GROUP_ITEM = re.compile(r"^\t([A-Za-z_]\w*)(?=\s|,|=|\[|\*|$)")

# Anything bound inside a function body or signature. Over-collecting here only
# makes the checker quieter, never wronger.
LOCAL = re.compile(
    r"(?:^|[\s(,])([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|\breturn\b)"
    r"|\bfor\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:="
    r"|\bfunc\s*\(([^)]*)\)"
    r"|\bfunc\s+\w*\(([^)]*)\)"
)
# a.b -> b is a field or method, never a package-level name
SELECTOR = re.compile(r"\.\s*[A-Za-z_]\w*")
STRINGS = re.compile(r"`[^`]*`|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
COMMENT = re.compile(r"//.*?$|/\*.*?\*/", re.S | re.M)
IMPORT_NAME = re.compile(r'^\s*(?:([A-Za-z_]\w*)\s+)?"([^"]+)"')
IDENT = re.compile(r"\b([a-z][A-Za-z0-9_]*)\b")


def strip_noise(src: str) -> str:
    src = COMMENT.sub(" ", src)
    src = STRINGS.sub(' "" ', src)
    return src


def declarations(src: str):
    out = set()
    in_group = False
    depth = 0
    for line in src.splitlines():
        if in_group:
            if line == ")":
                in_group = False
                continue
            if depth == 0:
                m = GROUP_ITEM.match(line)
                if m:
                    out.add(m.group(1))
            depth = max(0, depth + line.count("{") - line.count("}"))
            continue
        if GROUP_OPEN.match(line):
            in_group, depth = True, 0
            continue
        for pat in (DECL_FUNC, DECL_TYPE, DECL_VAR):
            m = pat.match(line)
            if m:
                out.add(m.group(1))
                break
    return out


def imported(src: str):
    names = set()
    block = re.search(r"^import\s*\((.*?)^\)", src, re.S | re.M)
    lines = block.group(1).splitlines() if block else []
    single = re.match(r"^import\s+(.*)$", src, re.M)
    if single:
        lines.append(single.group(1))
    for line in lines:
        m = IMPORT_NAME.match(line)
        if m:
            names.add(m.group(1) or m.group(2).rsplit("/", 1)[-1])
    return names


def bound_locally(src: str):
    """Every identifier that could be a local, parameter, field or label."""
    names = set()
    for m in LOCAL.finditer(src):
        for grp in m.groups():
            if not grp:
                continue
            for part in re.split(r"[,\s]+", grp):
                part = part.strip("*[]&")
                if re.fullmatch(r"[A-Za-z_]\w*", part or ""):
                    names.add(part)
    # Struct field names, including multi-name fields ("ihdIP, ihdHost string")
    # and fields whose type is a func or channel ("parseSlot chan struct{}",
    # "descFor func(b band) string"). The first version took only the first
    # name and only simple types, which is where its remaining false positives
    # came from.
    for m in re.finditer(
        r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
        r"(?:chan\b|func\b|map\[|\[|\*|<-|[A-Za-z_])[^\n=]*$", src, re.M):
        for part in m.group(1).split(","):
            names.add(part.strip())
    # A parameter whose type is itself a func, which can sit on a continuation
    # line of a multi-line signature: "labelFor func(b band) string, descFor
    # func(b band, p Point) string)". The nested parentheses defeat the simple
    # parameter scan below.
    for m in re.finditer(r"([A-Za-z_]\w*)\s+func\s*\(", src):
        names.add(m.group(1))
    # types declared inside a function body
    for m in re.finditer(r"^[ \t]+type\s+([A-Za-z_]\w*)", src, re.M):
        names.add(m.group(1))
    # indented "var a, b bool" / "var n int64 = -1" inside a function body —
    # the first pass missed these entirely and produced 76 false positives,
    # which would have made the checker worthless.
    for m in re.finditer(r"^[ \t]+(?:var|const)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)", src, re.M):
        for part in m.group(1).split(","):
            names.add(part.strip())
    for m in re.finditer(r"\bfor\s+([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*:?=", src):
        names.update(m.groups())
    for m in re.finditer(r"\b(?:range|if|switch)\b[^\n{]*?\b([A-Za-z_]\w*)\s*:=", src):
        names.add(m.group(1))
    for m in re.finditer(r"\(([^)]*)\)", src):
        for part in m.group(1).split(","):
            toks = part.strip().split()
            if len(toks) >= 2 and re.fullmatch(r"[A-Za-z_]\w*", toks[0]):
                names.add(toks[0])
    return names


def main() -> int:
    pkgs = defaultdict(list)
    for f in sorted(ROOT.rglob("*.go")):
        pkgs[f.parent].append(f)

    problems = 0
    for pkg, files in sorted(pkgs.items()):
        declared, imports, locals_ = set(), set(), set()
        sources = {}
        for f in files:
            raw = f.read_text(encoding="utf-8", errors="replace")
            src = strip_noise(raw)
            sources[f] = src
            declared |= declarations(src)
            imports |= imported(raw)
            locals_ |= bound_locally(src)
        known = declared | imports | locals_ | PREDECLARED

        for f, src in sources.items():
            body = SELECTOR.sub(" ", src)
            for n, line in enumerate(body.splitlines(), 1):
                for name in IDENT.findall(line):
                    if name in known:
                        continue
                    # only flag project-shaped names: a regex/helper like
                    # gpEnforcerEmptyRe, not a stray word
                    if len(name) < 6 or name.islower():
                        continue
                    problems += 1
                    print(f"{f.relative_to(ROOT)}:{n}: undefined in package: {name}")

    print("no undefined package identifiers" if not problems
          else f"\n{problems} possible undefined identifier(s) — likely a compile error")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
