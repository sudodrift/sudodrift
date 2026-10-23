package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/permdrift/permdrift/internal/fixture"
)

func runCLI(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, &o, &e)
	return c, o.String(), e.String()
}

func TestEndToEnd(t *testing.T) {
	root, tmp := t.TempDir(), t.TempDir()
	base, cur, rep := filepath.Join(tmp, "base.json"), filepath.Join(tmp, "cur.json"), filepath.Join(tmp, "r.html")

	fixture.Base(t, root)
	if c, _, e := runCLI("snapshot", "-o", base, "--root", root); c != 0 {
		t.Fatalf("snapshot exit %d: %s", c, e)
	}
	// same state -> no drift, exit 0
	if c, _, e := runCLI("snapshot", "--root", root, "-o", cur); c != 0 {
		t.Fatalf("snapshot exit %d: %s", c, e)
	}
	if c, out, _ := runCLI("diff", base, cur); c != 0 || !strings.Contains(out, "No drift detected") {
		t.Fatalf("expected no drift, exit=%d out=%s", c, out)
	}

	fixture.Drift(t, root)
	if c, _, e := runCLI("snapshot", "-o", cur, "--root", root); c != 0 {
		t.Fatalf("snapshot exit %d: %s", c, e)
	}
	c, out, _ := runCLI("diff", base, cur)
	if c != 1 {
		t.Fatalf("expected exit 1 on drift, got %d", c)
	}
	for _, w := range []string{"user bob added to group sudo", "SSH key " + fixture.BobFP + " added for user bob", "NOPASSWD", "/usr/bin/foo is now SUID"} {
		if !strings.Contains(out, w) {
			t.Errorf("diff output missing %q\n%s", w, out)
		}
	}

	// flags after positionals + ignore file
	ign := filepath.Join(tmp, "ignore.yaml")
	os.WriteFile(ign, []byte("ignore:\n  - \"suid:/usr/bin/foo\"\n"), 0o600)
	c, out, _ = runCLI("diff", base, cur, "--ignore", ign, "--min-severity", "high")
	if c != 1 || strings.Contains(out, "/usr/bin/foo") || strings.Contains(out, "[MEDIUM") {
		t.Errorf("ignore/min-severity not applied (exit %d):\n%s", c, out)
	}

	if c, _, e := runCLI("report", base, cur, "-o", rep); c != 0 {
		t.Fatalf("report exit %d: %s", c, e)
	}
	b, err := os.ReadFile(rep)
	if err != nil || !strings.Contains(string(b), "Total changes") {
		t.Errorf("report not written properly: %v", err)
	}
}

func TestErrors(t *testing.T) {
	if c, _, _ := runCLI(); c != 2 {
		t.Error("no args should exit 2")
	}
	if c, _, _ := runCLI("bogus"); c != 2 {
		t.Error("unknown command should exit 2")
	}
	if c, _, _ := runCLI("diff", "only-one.json"); c != 2 {
		t.Error("diff with one arg should exit 2")
	}
	if c, _, _ := runCLI("diff", "/nope/a.json", "/nope/b.json"); c != 2 {
		t.Error("missing files should exit 2")
	}
	if c, _, _ := runCLI("snapshot", "--root", "/definitely/not/here"); c != 2 {
		t.Error("bad root should exit 2")
	}
	if c, out, _ := runCLI("version"); c != 0 || !strings.Contains(out, "permdrift") {
		t.Error("version")
	}
}

func TestBadSnapshotsExit2(t *testing.T) {
	tmp := t.TempDir()
	root := t.TempDir()
	fixture.Base(t, root)
	good := filepath.Join(tmp, "good.json")
	if c, _, e := runCLI("snapshot", "--root", root, "-o", good); c != 0 {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(good)
	write := func(name, content string) string {
		p := filepath.Join(tmp, name)
		os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	cases := map[string]string{
		"corrupt":   write("corrupt.json", "{not json"),
		"empty":     write("empty.json", ""),
		"object":    write("obj.json", "{}"),
		"version":   write("v99.json", strings.Replace(string(b), `"schema": 1`, `"schema": 99`, 1)),
		"wrongtool": write("tool.json", strings.Replace(string(b), `"permdrift"`, `"other"`, 1)),
	}
	for name, p := range cases {
		for _, cmd := range [][]string{{"diff", good, p}, {"diff", p, good}, {"report", good, p, "-o", filepath.Join(tmp, "r.html")}} {
			c, out, e := runCLI(cmd...)
			if c != 2 || out != "" || !strings.Contains(e, filepath.Base(p)) {
				t.Errorf("%s %v: exit=%d stdout=%q stderr=%q (want exit 2 naming the file)", name, cmd[0], c, out, e)
			}
		}
	}
	if !strings.Contains(runErr(t, "diff", good, cases["version"]), "unsupported snapshot") {
		t.Error("version mismatch should say 'unsupported snapshot'")
	}
}

func runErr(t *testing.T, args ...string) string {
	t.Helper()
	_, _, e := runCLI(args...)
	return e
}

func TestSubcommandHelp(t *testing.T) {
	for _, sub := range []string{"snapshot", "diff", "report", "evidence"} {
		for _, h := range []string{"-h", "--help"} {
			c, _, e := runCLI(sub, h)
			if c != 0 || !strings.Contains(e, "Usage: permdrift "+sub) {
				t.Errorf("%s %s: exit=%d stderr=%q", sub, h, c, e)
			}
		}
	}
}

func TestBadFlagReportedOnce(t *testing.T) {
	c, _, e := runCLI("diff", "--bogus")
	if c != 2 || strings.Count(e, "not defined") != 1 {
		t.Errorf("exit=%d stderr=%q", c, e)
	}
}

func TestMinSeverityAndExitCodes(t *testing.T) {
	root, tmp := t.TempDir(), t.TempDir()
	base, cur := filepath.Join(tmp, "b.json"), filepath.Join(tmp, "c.json")
	fixture.Base(t, root)
	runCLI("snapshot", "--root", root, "-o", base)
	fixture.Drift(t, root)
	runCLI("snapshot", "--root", root, "-o", cur)
	// everything is below an impossible threshold only if nothing is High
	c, out, _ := runCLI("diff", base, cur, "--min-severity", "high")
	if c != 1 || strings.Contains(out, "[MEDIUM") || strings.Contains(out, "[LOW") || !strings.Contains(out, "[HIGH") {
		t.Errorf("--min-severity high: exit=%d\n%s", c, out)
	}
	if c, _, _ := runCLI("diff", base, cur, "--min-severity", "nope"); c != 2 {
		t.Errorf("bad severity should exit 2, got %d", c)
	}
	if c, _, _ := runCLI("diff", base, base); c != 0 {
		t.Errorf("identical snapshots should exit 0, got %d", c)
	}
}
