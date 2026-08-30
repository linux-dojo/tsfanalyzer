#!/usr/bin/env python3
"""Brace/paren/bracket balance check for Go files.

Catches the syntax errors that scripted edits introduce, which a compiler would
catch but there is no compiler here. Comments, strings, raw strings and rune
literals are skipped so their contents cannot be mistaken for delimiters.
"""
import sys, glob, os

def check(path):
    s = open(path, encoding="utf-8").read()
    i, n, line, stack = 0, len(s), 1, []
    pairs = {")": "(", "]": "[", "}": "{"}
    while i < n:
        c = s[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c == "/" and i + 1 < n and s[i+1] == "/":
            while i < n and s[i] != "\n": i += 1
            continue
        if c == "/" and i + 1 < n and s[i+1] == "*":
            i += 2
            while i + 1 < n and not (s[i] == "*" and s[i+1] == "/"):
                if s[i] == "\n": line += 1
                i += 1
            i += 2; continue
        if c == "`":
            i += 1
            while i < n and s[i] != "`":
                if s[i] == "\n": line += 1
                i += 1
            i += 1; continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == "\\": i += 1
                if i < n and s[i] == "\n": return f"{path}:{line}: unterminated string"
                i += 1
            i += 1; continue
        if c == "'":
            j = i + 1
            while j < n and s[j] != "'":
                if s[j] == "\\": j += 1
                j += 1
            if j < n and "\n" not in s[i:j]:
                i = j + 1; continue
            i += 1; continue
        if c in "([{":
            stack.append((c, line)); i += 1; continue
        if c in ")]}":
            if not stack: return f"{path}:{line}: unmatched {c}"
            o, l = stack.pop()
            if o != pairs[c]: return f"{path}:{line}: {c} closes {o} opened at line {l}"
            i += 1; continue
        i += 1
    if stack:
        o, l = stack[-1]
        return f"{path}: unclosed {o} opened at line {l}"
    return None

def main(paths):
    bad = 0
    for p in paths:
        r = check(p)
        if r:
            print(r); bad = 1
    print("balance: all ok" if not bad else "BALANCE PROBLEMS FOUND")
    return bad

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        args = sorted(glob.glob(os.path.join(root, "backend", "**", "*.go"), recursive=True))
    sys.exit(main(args))
