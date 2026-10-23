package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sudodrift/sudodrift/internal/fixture"
)

// driftPair builds a fake root, takes a base snapshot, applies the drift
// fixture and takes a second snapshot.
func driftPair(t *testing.T) (base, cur string) {
	t.Helper()
	root, tmp := t.TempDir(), t.TempDir()
	base, cur = filepath.Join(tmp, "base.json"), filepath.Join(tmp, "now.json")
	fixture.Base(t, root)
	if c, _, e := runCLI("snapshot", "--root", root, "-o", base); c != 0 {
		t.Fatal(e)
	}
	fixture.Drift(t, root)
	if c, _, e := runCLI("snapshot", "--root", root, "-o", cur); c != 0 {
		t.Fatal(e)
	}
	return base, cur
}

func TestDiffFormatJSON(t *testing.T) {
	base, cur := driftPair(t)
	c, out, _ := runCLI("diff", base, cur, "--format", "json")
	if c != 1 {
		t.Fatalf("drift with --format json must still exit 1, got %d", c)
	}
	var doc struct {
		Version int `json:"version"`
		Summary struct{ Total, High int }
		Changes []struct{ Type, Category, Subject, Severity, Message string }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not json: %v\n%s", err, out)
	}
	if doc.Version != 1 || doc.Summary.Total != len(doc.Changes) || doc.Summary.High == 0 {
		t.Errorf("doc = %+v", doc)
	}
	// the same flag with --min-severity and the equals form
	c, out, _ = runCLI("diff", base, cur, "--format=json", "--min-severity", "high")
	if c != 1 || strings.Contains(out, `"Medium"`) {
		t.Errorf("min-severity not applied to json (exit %d)", c)
	}
	// no drift: valid json, empty list, exit 0
	c, out, _ = runCLI("diff", base, base, "--format", "json")
	if c != 0 || !strings.Contains(out, `"changes": []`) || !strings.Contains(out, `"total": 0`) {
		t.Errorf("no drift: exit=%d\n%s", c, out)
	}
}

func TestDiffFormatCSV(t *testing.T) {
	base, cur := driftPair(t)
	c, out, _ := runCLI("diff", base, cur, "--format", "csv")
	if c != 1 {
		t.Fatalf("exit %d", c)
	}
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("csv: %v rows=%d", err, len(rows))
	}
	if strings.Join(rows[0], ",") != "severity,type,category,subject,message" {
		t.Errorf("header %v", rows[0])
	}
	for _, r := range rows[1:] {
		if len(r) != 5 {
			t.Errorf("row has %d columns: %q", len(r), r)
		}
	}
	c, out, _ = runCLI("diff", base, base, "--format", "csv")
	if c != 0 || out != "severity,type,category,subject,message\n" {
		t.Errorf("no drift csv: exit=%d %q", c, out)
	}
}

func TestDiffFormatTextIsDefault(t *testing.T) {
	base, cur := driftPair(t)
	_, def, _ := runCLI("diff", base, cur)
	c, txt, _ := runCLI("diff", base, cur, "--format", "text")
	if c != 1 || def != txt || !strings.Contains(def, "DRIFT DETECTED") {
		t.Errorf("explicit text must equal the default (exit %d)", c)
	}
}

func TestDiffBadFormat(t *testing.T) {
	base, cur := driftPair(t)
	c, out, e := runCLI("diff", base, cur, "--format", "xml")
	if c != 2 || out != "" || !strings.Contains(e, `unknown format "xml"`) {
		t.Errorf("exit=%d out=%q err=%q", c, out, e)
	}
	// report does not take --format
	if c, _, _ := runCLI("report", base, cur, "-o", filepath.Join(t.TempDir(), "r.html"), "--format", "json"); c != 2 {
		t.Errorf("report --format should be a usage error, got %d", c)
	}
}

// CSV injection through a real hostile file name travels from a fake root to
// the CSV and must come out defanged.
func TestDiffCSVInjectionEndToEnd(t *testing.T) {
	root, tmp := t.TempDir(), t.TempDir()
	fixture.Base(t, root)
	base, cur := filepath.Join(tmp, "b.json"), filepath.Join(tmp, "c.json")
	runCLI("snapshot", "--root", root, "-o", base)
	fixture.Write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+
		"=cmd|' /C calc'!A0:x:2001:2001::/home/a:/bin/bash\n"+
		"-2+3:x:2002:2002::/home/b:/bin/bash\n"+
		"@SUM(1+1):x:2003:2003::/home/c:/bin/bash\n"+
		"+1:x:2004:2004::/home/d:/bin/bash\n", 0o644)
	runCLI("snapshot", "--root", root, "-o", cur)
	_, out, _ := runCLI("diff", base, cur, "--format", "csv")
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range rows[1:] {
		for _, cell := range r {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("unprotected cell %q", cell)
			}
			if len(cell) > 1 && cell[0] == '\'' && strings.ContainsRune("=+-@", rune(cell[1])) {
				found++
			}
		}
	}
	if found < 4 {
		t.Errorf("expected defanged cells in:\n%s", out)
	}
}

type bundle map[string][]byte

func readZip(t *testing.T, path string) (bundle, string) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	b := bundle{}
	top := ""
	for _, f := range zr.File {
		dir, name, ok := strings.Cut(f.Name, "/")
		if !ok {
			t.Fatalf("entry %q has no top-level folder", f.Name)
		}
		if top != "" && dir != top {
			t.Fatalf("several top-level folders: %q and %q", top, dir)
		}
		top = dir
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		b[name] = data
	}
	return b, top
}

func checkManifest(t *testing.T, b bundle) {
	t.Helper()
	n := 0
	sc := bufio.NewScanner(strings.NewReader(string(b["MANIFEST.sha256"])))
	for sc.Scan() {
		hash, name, _ := strings.Cut(sc.Text(), "  ")
		sum := sha256.Sum256(b[name])
		if len(b[name]) == 0 || hex.EncodeToString(sum[:]) != hash {
			t.Errorf("manifest entry %q does not match", name)
		}
		n++
	}
	if n != len(b)-1 {
		t.Errorf("manifest has %d entries for %d files", n, len(b)-1)
	}
}

func TestEvidenceZipEndToEnd(t *testing.T) {
	base, cur := driftPair(t)
	out := filepath.Join(t.TempDir(), "evidence-demo-host-2026-01-02.zip")
	c, stdout, e := runCLI("evidence", "--base", base, "--current", cur, "-o", out)
	if c != 0 || stdout != "" || !strings.Contains(e, "not a signature") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", c, stdout, e)
	}
	b, top := readZip(t, out)
	if top != "evidence-demo-host-2026-01-02" {
		t.Errorf("top folder %q", top)
	}
	for _, n := range []string{"base.json", "current.json", "diff.txt", "diff.json", "report.html", "REVIEW.md", "metadata.json", "MANIFEST.sha256"} {
		if len(b[n]) == 0 {
			t.Errorf("missing %s", n)
		}
	}
	checkManifest(t, b)
	// inputs are the untouched files
	for name, path := range map[string]string{"base.json": base, "current.json": cur} {
		want, _ := os.ReadFile(path)
		if string(b[name]) != string(want) {
			t.Errorf("%s differs from the input file", name)
		}
	}
	// diff.txt equals what `sudodrift diff` prints
	_, txt, _ := runCLI("diff", base, cur)
	if string(b["diff.txt"]) != txt {
		t.Error("diff.txt differs from sudodrift diff output")
	}
	var md struct {
		ToolVersion string `json:"tool_version"`
		GeneratedAt string `json:"generated_at"`
		Total       int    `json:"total_changes"`
	}
	if err := json.Unmarshal(b["metadata.json"], &md); err != nil || md.ToolVersion != version || md.GeneratedAt == "" || md.Total == 0 {
		t.Errorf("metadata: %v %+v", err, md)
	}
	if !strings.Contains(string(b["REVIEW.md"]), "Reviewer name:") || !strings.Contains(string(b["REVIEW.md"]), "### H1.") {
		t.Error("REVIEW.md incomplete")
	}
	// second run refuses to overwrite, --force replaces
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur, "-o", out); c != 2 || !strings.Contains(e, "already exists") {
		t.Errorf("overwrite: exit=%d %q", c, e)
	}
	if c, _, _ := runCLI("evidence", "--base", base, "--current", cur, "-o", out, "--force"); c != 0 {
		t.Errorf("--force exit %d", c)
	}
}

func TestEvidenceDirAndDefaultName(t *testing.T) {
	base, cur := driftPair(t)
	d := filepath.Join(t.TempDir(), "bundle")
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur, "--dir", d); c != 0 {
		t.Fatal(e)
	}
	b := bundle{}
	ents, _ := os.ReadDir(d)
	for _, en := range ents {
		b[en.Name()], _ = os.ReadFile(filepath.Join(d, en.Name()))
	}
	if len(b) != 8 {
		t.Errorf("want 8 files, got %d", len(b))
	}
	checkManifest(t, b)
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur, "--dir", d); c != 2 || !strings.Contains(e, "not empty") {
		t.Errorf("non-empty dir: exit=%d %q", c, e)
	}

	// no -o and no --dir: evidence-<host>-<date>.zip in the current directory
	wd, _ := os.Getwd()
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur); c != 0 {
		t.Fatal(e)
	}
	m, _ := filepath.Glob(filepath.Join(work, "evidence-demo-host-????-??-??.zip"))
	if len(m) != 1 {
		t.Errorf("default file name not found, got %v", m)
	}
}

func TestEvidenceOptionsAndErrors(t *testing.T) {
	base, cur := driftPair(t)
	tmp := t.TempDir()
	out := filepath.Join(tmp, "e.zip")
	ign := filepath.Join(tmp, "ignore.txt")
	os.WriteFile(ign, []byte("suid:/usr/bin/foo\n"), 0o600)
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur, "-o", out, "--ignore", ign, "--min-severity", "high"); c != 0 {
		t.Fatal(e)
	}
	b, _ := readZip(t, out)
	if strings.Contains(string(b["diff.txt"]), "[MEDIUM") || strings.Contains(string(b["diff.json"]), `"Medium"`) {
		t.Error("min-severity not applied in the bundle")
	}
	var md struct {
		MinSeverity string `json:"min_severity"`
		IgnoreFile  string `json:"ignore_file"`
	}
	json.Unmarshal(b["metadata.json"], &md)
	if md.MinSeverity != "high" || md.IgnoreFile != "ignore.txt" {
		t.Errorf("metadata = %+v", md)
	}
	if strings.Contains(string(b["metadata.json"]), tmp) {
		t.Error("metadata must not contain local directory paths")
	}

	for name, args := range map[string][]string{
		"no flags":       {"evidence"},
		"no current":     {"evidence", "--base", base},
		"positional":     {"evidence", base, cur},
		"both outputs":   {"evidence", "--base", base, "--current", cur, "-o", "x.zip", "--dir", "x"},
		"missing file":   {"evidence", "--base", base, "--current", "/nope.json"},
		"bad severity":   {"evidence", "--base", base, "--current", cur, "--min-severity", "x"},
		"bad ignore":     {"evidence", "--base", base, "--current", cur, "--ignore", "/nope.txt"},
		"missing outdir": {"evidence", "--base", base, "--current", cur, "-o", filepath.Join(tmp, "no", "e.zip")},
	} {
		if c, o, e := runCLI(args...); c != 2 || o != "" || e == "" {
			t.Errorf("%s: exit=%d stdout=%q stderr=%q", name, c, o, e)
		}
	}
}

// Hostile host names and file names must not break out of the HTML report,
// the review file or the zip file name.
func TestEvidenceHostileNames(t *testing.T) {
	root, tmp := t.TempDir(), t.TempDir()
	fixture.Base(t, root)
	base, cur := filepath.Join(tmp, "b.json"), filepath.Join(tmp, "c.json")
	runCLI("snapshot", "--root", root, "-o", base)
	fixture.Write(t, root, "etc/hostname", "../<script>alert(1)</script>\n", 0o644)
	fixture.Write(t, root, `usr/bin/x"><script>alert(2)</script>`, "x", 0o4755)
	runCLI("snapshot", "--root", root, "-o", cur)

	work := t.TempDir()
	wd, _ := os.Getwd()
	os.Chdir(work)
	defer os.Chdir(wd)
	if c, _, e := runCLI("evidence", "--base", base, "--current", cur); c != 0 {
		t.Fatal(e)
	}
	ents, _ := os.ReadDir(work)
	if len(ents) != 1 || strings.ContainsAny(ents[0].Name(), "<>/\\") || !strings.HasPrefix(ents[0].Name(), "evidence-") {
		t.Fatalf("unsafe or missing output name: %v", ents)
	}
	b, top := readZip(t, filepath.Join(work, ents[0].Name()))
	if strings.ContainsAny(top, "<>\\") || strings.Contains(top, "..") {
		t.Errorf("unsafe top folder %q", top)
	}
	for _, n := range []string{"report.html", "REVIEW.md"} {
		if strings.Contains(string(b[n]), "<script") {
			t.Errorf("%s contains an unescaped <script", n)
		}
	}
	if !strings.Contains(string(b["report.html"]), "&lt;script&gt;") {
		t.Error("expected the hostile name to show up escaped in report.html")
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("short mode")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	bin := filepath.Join(t.TempDir(), "sudodrift")
	cmd := exec.Command(goBin, "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the binary here: %v\n%s", err, out)
	}
	return bin
}

// The example scripts under examples/systemd run against the real binary and
// a fake root.
func TestExampleScripts(t *testing.T) {
	bin := buildBinary(t)
	scripts := filepath.Join("..", "..", "examples", "systemd")
	root, snaps, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	fixture.Base(t, root)
	// Snapshot through the real binary with a fake root: the script calls
	// "sudodrift snapshot" with no --root, so use a wrapper that adds it.
	wrapper := filepath.Join(tmp, "pd")
	os.WriteFile(wrapper, []byte("#!/bin/sh\nif [ \"$1\" = snapshot ]; then exec "+bin+" \"$@\" --root "+root+"; fi\nexec "+bin+" \"$@\"\n"), 0o755)
	run := func(script string, env []string, args ...string) (int, string) {
		cmd := exec.Command("sh", append([]string{filepath.Join(scripts, script)}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}
	env := []string{"SUDODRIFT_BIN=" + wrapper, "SUDODRIFT_DIR=" + snaps, "SUDODRIFT_KEEP=2"}

	// no snapshots yet
	if c, out := run("sudodrift-check.sh", env, "-q", filepath.Join(tmp, "baseline.json"), snaps); c != 2 || !strings.Contains(out, "no snapshots") {
		t.Errorf("empty dir: exit=%d %s", c, out)
	}
	// baseline taken by hand
	baseline := filepath.Join(tmp, "baseline.json")
	if c, out := run("sudodrift-snapshot.sh", env); c != 0 {
		t.Fatalf("snapshot script: %d %s", c, out)
	}
	ents, _ := os.ReadDir(snaps)
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "snapshot-") {
		t.Fatalf("snapshots dir: %v", ents)
	}
	data, _ := os.ReadFile(filepath.Join(snaps, ents[0].Name()))
	os.WriteFile(baseline, data, 0o600)
	// fake older dated files to test pruning
	for _, n := range []string{"snapshot-2020-01-01.json", "snapshot-2020-02-01.json", "snapshot-2020-03-01.json"} {
		os.WriteFile(filepath.Join(snaps, n), data, 0o600)
	}
	if c, out := run("sudodrift-snapshot.sh", env); c != 0 {
		t.Fatalf("second snapshot script run: %d %s", c, out)
	}
	left, _ := filepath.Glob(filepath.Join(snaps, "snapshot-*.json"))
	if len(left) != 2 {
		t.Errorf("KEEP=2 should leave 2 files, got %v", left)
	}
	if m, _ := filepath.Glob(filepath.Join(snaps, "*.tmp")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}

	// no drift: exit 0, quiet mode prints nothing
	if c, out := run("sudodrift-check.sh", env, "-q", baseline, snaps); c != 0 || out != "" {
		t.Errorf("clean quiet check: exit=%d out=%q", c, out)
	}
	if c, out := run("sudodrift-check.sh", env, baseline, snaps); c != 0 || !strings.Contains(out, "No drift detected") {
		t.Errorf("clean check: exit=%d out=%q", c, out)
	}
	// drift: take a new snapshot after tampering, check exits 1
	fixture.Drift(t, root)
	today := filepath.Join(snaps, "snapshot-2999-01-01.json")
	if c, _, e := runCLI("snapshot", "--root", root, "-o", today); c != 0 {
		t.Fatal(e)
	}
	c, out := run("sudodrift-check.sh", env, "-q", baseline, snaps)
	if c != 1 || !strings.Contains(out, "DRIFT DETECTED") || !strings.Contains(out, "snapshot-2999-01-01.json") {
		t.Errorf("drift check: exit=%d out=%q", c, out)
	}
	// the newest file being the baseline is an error, not a silent pass
	if c, _ := run("sudodrift-check.sh", env, today, snaps); c != 2 {
		t.Errorf("newest == baseline should exit 2, got %d", c)
	}
	// missing baseline argument
	if c, _ := run("sudodrift-check.sh", env); c != 2 && c != 1 {
		t.Errorf("missing argument should fail, got %d", c)
	}
}
