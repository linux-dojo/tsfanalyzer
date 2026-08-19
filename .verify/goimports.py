#!/usr/bin/env python3
"""Check Go import blocks in both directions: imported-but-unused AND
used-but-not-imported.

This exists because a hand-rolled checker that only looked for unused imports
missed `undefined: sort` in gpflow.go — the far more likely mistake when adding
code to an existing file. It also got the "unused" direction wrong by slicing
the file at the wrong offset, so it reported false positives on search.go.

There is no Go compiler in this environment, so this is the closest available
substitute for the one error class that has actually broken the build.
"""
import re
import sys
import glob
import os

# Package name -> the identifier it binds, where they differ.
BINDS = {
    "math/rand": "rand",
    "encoding/xml": "xml",
    "encoding/json": "json",
    "encoding/hex": "hex",
    "archive/tar": "tar",
    "archive/zip": "zip",
    "compress/gzip": "gzip",
    "crypto/rand": "rand",
    "net/http": "http",
    "net/http/httptest": "httptest",
    "path/filepath": "filepath",
    "regexp/syntax": "syntax",
    "unicode/utf8": "utf8",
    "mime/multipart": "multipart",
}

# Standard-library packages the code might reference. Only these are reported as
# "missing", so a local identifier is never mistaken for a package.
STDLIB = {
    "archive/tar", "archive/zip", "bufio", "bytes", "compress/gzip", "context",
    "encoding/hex", "encoding/json", "encoding/xml", "errors", "fmt", "io",
    "log", "math", "math/rand", "mime/multipart", "net/http", "net/http/httptest",
    "os", "path", "path/filepath", "regexp", "regexp/syntax", "sort", "strconv",
    "strings", "sync", "time", "unicode", "unicode/utf8",
}
IDENT_TO_PATH = {}
for p in STDLIB:
    IDENT_TO_PATH.setdefault(BINDS.get(p, p.split("/")[-1]), p)


def strip_code(s: str) -> str:
    """Remove comments and string/rune literals so only real code remains."""
    s = re.sub(r"`[^`]*`", "``", s, flags=re.S)          # raw strings
    s = re.sub(r'"(\\.|[^"\\\n])*"', '""', s)             # interpreted strings
    s = re.sub(r"'(\\.|[^'\\\n])'", "'x'", s)             # rune literals
    s = re.sub(r"//[^\n]*", "", s)                        # line comments
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)           # block comments
    return s


def check(path: str):
    raw = open(path, encoding="utf-8").read()
    problems = []

    m = re.search(r"^import\s*\((.*?)^\)", raw, re.M | re.S)
    if m:
        import_block, body_start = m.group(1), m.end()
    else:
        # Single-line form: `import "testing"` or `import alias "path"`. The
        # leading keyword must be dropped, or it is parsed as the alias — which
        # made this checker report the import as unused and hid the real name.
        m1 = re.search(r'^import\s+((?:\w+\s+)?"[^"]+")', raw, re.M)
        import_block = m1.group(1) if m1 else ""
        body_start = m1.end() if m1 else 0

    imported = {}   # bound identifier -> import path
    for line in import_block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        am = re.match(r'(?:(\w+|_|\.)\s+)?"([^"]+)"', line)
        if not am:
            continue
        alias, ipath = am.group(1), am.group(2)
        if alias in ("_", "."):
            continue
        imported[alias or BINDS.get(ipath, ipath.split("/")[-1])] = ipath

    # Only the body counts: the import block itself mentions every name.
    body = strip_code(raw[body_start:])
    referenced = set(re.findall(r"(?<![\w.])([a-z][a-z0-9]*)\s*\.", body))

    for ident, ipath in sorted(imported.items()):
        if ident not in referenced:
            problems.append(f"imported but not used: {ipath}")

    for ident in sorted(referenced):
        if ident in imported:
            continue
        if ident in IDENT_TO_PATH:
            # a local variable could shadow a package name, so require that the
            # identifier is never declared locally in this file
            declared = re.search(
                r"(?<![\w.])" + ident + r"\s*(?::=|,[^\n]*:=)|"
                r"\b(?:var|const)\s+" + ident + r"\b|"
                r"func\s+\w*\(\s*" + ident + r"\b|"
                r"\b" + ident + r"\s+[\w*\[\]]+\s*[,)]",
                body,
            )
            if not declared:
                problems.append(
                    f"used but not imported: {ident} (want \"{IDENT_TO_PATH[ident]}\")"
                )
    return problems


def main(paths):
    bad = 0
    for path in paths:
        if path.endswith("_test.go"):
            pass  # tests are compiled too, so they are checked as well
        probs = check(path)
        if probs:
            bad = 1
            for p in probs:
                print(f"{path}: {p}")
    print("no import problems found" if not bad else "IMPORT PROBLEMS FOUND")
    return bad


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        args = sorted(glob.glob(os.path.join(root, "backend", "**", "*.go"), recursive=True))
    sys.exit(main(args))
