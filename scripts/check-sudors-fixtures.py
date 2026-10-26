#!/usr/bin/env python3
"""Compare `sudodrift sudors-check` with the real sudo-rs visudo.

For every fixture under internal/sudors/testdata this runs sudors-check, then
runs `visudo -c -f` from sudo-rs on each file it read, and compares the lines
each one rejects. Include lines are commented out before visudo sees a file,
so visudo never reads files outside the fixture; include handling is covered
by the Go tests instead.

Usage: scripts/check-sudors-fixtures.py SUDODRIFT VISUDO TARGET
Example: scripts/check-sudors-fixtures.py bin/sudodrift ~/sudors-0.2.13/bin/visudo ubuntu-26.04
"""
import json, os, re, subprocess, sys, tempfile

sudodrift, visudo, target = sys.argv[1:4]
base = os.path.join(os.path.dirname(__file__), "..", "internal", "sudors", "testdata")
include_rules = {"includedir-percent-h", "include-percent-h", "include-missing", "include-limit"}
err_re = re.compile(r"^.*?:(\d+):\d+: syntax error: (.*)$")
total_ok = total_bad = 0

for name in sorted(os.listdir(base)):
    root = os.path.join(base, name)
    out = subprocess.run([sudodrift, "sudors-check", "--root", root, "--format", "json", "--target", target],
                         capture_output=True, text=True)
    rep = json.loads(out.stdout)
    for f in rep["files"]:
        ours = {x["line"] for x in rep["findings"]
                if x["file"] == f and x["severity"] == "breaks" and x["rule"] not in include_rules}
        with open(os.path.join(root, f.lstrip("/")), "rb") as fh:
            data = fh.read()
        lines = data.split(b"\n")
        # visudo reports the physical line; sudors-check reports the first
        # line of a backslash-continued logical line. Map one to the other.
        start, cont = {}, False
        for i, l in enumerate(lines, 1):
            if not cont:
                first = i
            start[i] = first
            cont = l.endswith(b"\\")
        lines = [b"#" + l if re.match(rb"^\s*[@#]include", l) else l for l in lines]
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"\n".join(lines))
        res = subprocess.run([visudo, "-c", "-f", tmp.name], capture_output=True)
        os.unlink(tmp.name)
        theirs, msgs = set(), {}
        for l in res.stdout.decode("utf-8", "replace").splitlines() + res.stderr.decode("utf-8", "replace").splitlines():
            m = err_re.match(l)
            if m and "this tag is ignored" not in m.group(2):
                n = start.get(int(m.group(1)), int(m.group(1)))
                theirs.add(n)
                msgs[n] = m.group(2)
            elif "stream did not contain valid UTF-8" in l or "invalid utf-8" in l.lower():
                theirs.add(-1)
                msgs[-1] = l.strip()
        if -1 in theirs:  # visudo refuses the whole file; we report the first bad line
            theirs.discard(-1)
            theirs |= {x["line"] for x in rep["findings"] if x["file"] == f and x["rule"] == "not-utf8"}
        same = ours == theirs
        total_ok += same
        total_bad += not same
        print(f"{'OK  ' if same else 'DIFF'} {name}{f}: sudors-check breaks={sorted(ours)} visudo errors={sorted(theirs)}")
        if not same:
            for n in sorted(theirs - ours):
                print(f"      only visudo, line {n}: {msgs.get(n, '')}")
            for n in sorted(ours - theirs):
                print(f"      only sudors-check, line {n}")
print(f"\n{total_ok} files agree, {total_bad} differ")
sys.exit(1 if total_bad else 0)
