#!/usr/bin/env python3
"""Render docs/demo.gif from a REAL run of the sudodrift binary.

Every command shown is actually executed (fake root in /tmp/demo-root, nothing
real is touched) and its captured output is what gets drawn. Only the colors
are added by this script, because sudodrift prints plain text.

Needs: Python 3, Pillow, DejaVu Sans Mono, a built bin/sudodrift.
Usage: python3 scripts/make-demo-gif.py
"""
import os, re, shutil, subprocess, sys, tempfile
from PIL import Image, ImageDraw, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO, "bin", "sudodrift")
OUT = os.path.join(REPO, "docs", "demo.gif")
SHOT = os.path.join(REPO, "docs", "report-screenshot.png")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

COLS, ROWS, FS, LH = 100, 25, 15, 20
f_reg, f_bold = ImageFont.truetype(FONT, FS), ImageFont.truetype(FONTB, FS)
CW = round(f_reg.getlength("M"))
PADX, TOP, BAR = 16, 14, 30
W, H = COLS * CW + 2 * PADX, ROWS * LH + TOP * 2 + BAR

BG, FG, DIM = (22, 25, 34), (212, 217, 228), (118, 128, 150)
GREEN, RED, YEL, BLUE, CYAN, ORANGE = (126, 214, 130), (255, 107, 107), (240, 205, 100), (110, 170, 255), (110, 215, 225), (255, 160, 80)
BARC = (36, 40, 52)

# ---- run the real tool -------------------------------------------------
work = tempfile.mkdtemp(prefix="demo-work-")
os.symlink(os.path.join(REPO, "scripts"), os.path.join(work, "scripts"))
bindir = os.path.join(work, "bin"); os.mkdir(bindir)
os.symlink(BIN, os.path.join(bindir, "sudodrift"))
with open(os.path.join(work, "bob.pub"), "w") as fh:
    fh.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIG2N9j80sbaY1nmljEToRcN55XktyW4TR4LTP2exYzp bob@laptop\n")
env = dict(os.environ, PATH=bindir + ":" + os.environ["PATH"], HOME="/home/demo", USER="demo", LOGNAME="demo")
R = "/tmp/demo-root"
STEPS = [
    ("# 1. build a fake root (no real files touched)", None),
    ("scripts/demo-root.sh " + R, "run"),
    ("# 2. baseline snapshot", None),
    ("sudodrift snapshot -o base.json --root " + R, "run"),
    ("# 3. now tamper with it: SSH key, NOPASSWD sudo, sudo group, SUID file", None),
    ("cat bob.pub >> %s/home/bob/.ssh/authorized_keys" % R, "run"),
    ('echo "bob ALL=(ALL) NOPASSWD: ALL" > %s/etc/sudoers.d/90-bob' % R, "run"),
    ("sed -i 's/^sudo:x:27:alice$/sudo:x:27:alice,bob/' %s/etc/group" % R, "run"),
    ("chmod 4755 %s/usr/bin/editor" % R, "run"),
    ("sudodrift snapshot -o now.json --root " + R, "run"),
    ("clear", "clear"),
    ("sudodrift diff base.json now.json", "run"),
]
results = []
for cmd, kind in STEPS:
    out = ""
    if kind == "run":
        p = subprocess.run(["bash", "-c", cmd], cwd=work, env=env, capture_output=True, text=True)
        out = p.stdout + p.stderr
    results.append((cmd, kind, out))
shutil.rmtree(R, ignore_errors=True)
shutil.rmtree(work, ignore_errors=True)

# ---- styling -------------------------------------------------------------
def style_output(line):
    cols = [FG] * len(line)
    def paint(a, b, c):
        for i in range(a, min(b, len(line))): cols[i] = c
    m = re.match(r"\[(HIGH  |MEDIUM|LOW   )\] (added  |removed|changed) (\S+\s*)", line)
    if m:
        sev = m.group(1).strip()
        paint(0, 8, {"HIGH": RED, "MEDIUM": ORANGE, "LOW": BLUE}[sev])
        paint(9, 16, {"added": GREEN, "removed": RED, "changed": YEL}[m.group(2).strip()])
        paint(17, m.end(), CYAN)
    elif line.startswith("DRIFT DETECTED"):
        paint(0, len(line), RED)
    elif line.startswith(("base:", "current:")):
        paint(0, len(line), DIM)
    elif line.startswith("fake root ready"):
        paint(0, len(line), GREEN)
    return cols

def style_cmd(cmd):
    if cmd.startswith("#"): return [DIM] * len(cmd)
    cols = [FG] * len(cmd)
    first = cmd.split(" ")[0]
    for i in range(len(first)): cols[i] = GREEN if first == "sudodrift" else FG
    for m in re.finditer(r"(?<= )-{1,2}\w[\w-]*", cmd):
        for i in range(m.start(), m.end()): cols[i] = YEL
    return cols

# ---- terminal model ------------------------------------------------------
class Term:
    def __init__(self):
        self.rows = [[]]  # each row: list of (char, color, bold)
    def put(self, ch, col, bold=False):
        if len(self.rows[-1]) >= COLS: self.rows.append([])
        self.rows[-1].append((ch, col, bold))
    def nl(self): self.rows.append([])
    def clear(self): self.rows = [[]]
    def draw(self, cursor=True, caption=None):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, BAR], fill=BARC)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([14 + i * 22, 9, 26 + i * 22, 21], fill=c)
        t = "sudodrift demo"
        d.text((W // 2 - f_reg.getlength(t) / 2, 6), t, font=f_reg, fill=DIM)
        vis = self.rows[-ROWS:]
        for r, row in enumerate(vis):
            y = BAR + TOP + r * LH
            for c, (ch, col, bold) in enumerate(row):
                if ch != " ":
                    d.text((PADX + c * CW, y), ch, font=f_bold if bold else f_reg, fill=col)
        if cursor:
            r, c = len(vis) - 1, len(vis[-1])
            if c >= COLS: r, c = r + 1, 0
            if r < ROWS:
                d.rectangle([PADX + c * CW, BAR + TOP + r * LH + 2, PADX + c * CW + CW - 2, BAR + TOP + r * LH + LH - 2], fill=FG)
        return img

frames, delays = [], []
def snap(term, ms, cursor=True):
    frames.append(term.draw(cursor)); delays.append(ms)

term = Term()
def prompt():
    term.put("$", GREEN, True); term.put(" ", FG)

TYPE_MS, STEP = 15, 2
snap(term, 300)
prompt(); snap(term, 600)
first = True
for cmd, kind, out in results:
    if not first: prompt()
    first = False
    cols = style_cmd(cmd)
    comment = cmd.startswith("#")
    for i, ch in enumerate(cmd):
        term.put(ch, cols[i])
        if i % STEP == STEP - 1 or i == len(cmd) - 1:
            snap(term, TYPE_MS * STEP if not comment else 9 * STEP)
    snap(term, 250 if comment else 450)
    if kind == "clear":
        term.clear(); prompt(); snap(term, 200); first = True
        continue
    term.nl()
    lines = out.rstrip("\n").split("\n") if out.strip() else []
    slow = cmd.startswith("sudodrift diff")
    for ln in lines:
        if ln == "": term.nl(); continue
        cs = style_output(ln)
        for ch, col in zip(ln, cs): term.put(ch, col)
        term.nl()
        if slow: snap(term, 90)
    if lines and not slow: snap(term, 350)
    elif not lines: snap(term, 150)
prompt(); snap(term, 2800)
# final terminal frame holds, then the HTML report
shot = Image.open(SHOT).convert("RGB")
sh = H - 30 - 16
shot = shot.resize((round(shot.width * sh / shot.height), sh), Image.LANCZOS)
rep = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(rep)
d.rectangle([0, 0, W, 30], fill=BARC)
cap = "$ sudodrift report base.json now.json -o report.html    # HTML report (larger sample)"
d.text((PADX, 6), cap, font=f_reg, fill=GREEN)
rep.paste(shot, ((W - shot.width) // 2, 30 + 8))
frames.append(rep); delays.append(4500)

# ---- save ----------------------------------------------------------------
sample = [frames[-2], frames[len(frames) // 2], frames[len(frames) // 4]]
mosaic = Image.new("RGB", (W, H * len(sample)))
for i, s_ in enumerate(sample): mosaic.paste(s_, (0, H * i))
palimg = mosaic.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
q = [f.quantize(palette=palimg, dither=Image.Dither.NONE) for f in frames[:-1]]
q.append(frames[-1].quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
q[0].save(OUT, save_all=True, append_images=q[1:], duration=delays, loop=0, optimize=True, disposal=1)
print("frames=%d total=%.1fs size=%d bytes -> %s" % (len(q), sum(delays) / 1000, os.path.getsize(OUT), OUT))
