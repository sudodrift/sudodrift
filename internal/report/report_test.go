package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sudodrift/sudodrift/internal/diff"
	"github.com/sudodrift/sudodrift/internal/fixture"
	"github.com/sudodrift/sudodrift/internal/snapshot"
)

func input(t *testing.T) Input {
	root := t.TempDir()
	fixture.Base(t, root)
	base, _ := snapshot.Collect(snapshot.Options{Root: root})
	fixture.Drift(t, root)
	cur, _ := snapshot.Collect(snapshot.Options{Root: root})
	return Input{Base: base, Current: cur, Changes: diff.Compare(base, cur), ToolVersion: "test"}
}

func TestHTMLSelfContained(t *testing.T) {
	in := input(t)
	var buf bytes.Buffer
	if err := WriteHTML(&buf, in); err != nil {
		t.Fatal(err)
	}
	h := buf.String()
	for _, want := range []string{"<style>", "Total changes", "t-added", "t-changed", `badge high`, "user bob added to group sudo", "demo-host"} {
		if !strings.Contains(h, want) {
			t.Errorf("html missing %q", want)
		}
	}
	for _, bad := range []string{"<script", "<link", "http://", "https://", "src=", "@import", "url("} {
		if strings.Contains(h, bad) {
			t.Errorf("html must be self-contained, found %q", bad)
		}
	}
}

func TestHTMLEscapes(t *testing.T) {
	in := input(t)
	in.Changes = []diff.Change{{Type: diff.Added, Category: "x", Subject: "s", Severity: diff.Low, Message: `<img src=x onerror=alert(1)>`}}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<img src=x") {
		t.Error("message not escaped")
	}
}

func TestNoDriftAndText(t *testing.T) {
	in := input(t)
	in.Changes = nil
	var buf bytes.Buffer
	WriteText(&buf, in)
	if !strings.Contains(buf.String(), "No drift detected.") {
		t.Error(buf.String())
	}
	buf.Reset()
	if err := WriteHTML(&buf, in); err != nil || !strings.Contains(buf.String(), "No drift detected") {
		t.Error("html no-drift banner missing")
	}
	in = input(t)
	buf.Reset()
	WriteText(&buf, in)
	if !strings.Contains(buf.String(), "DRIFT DETECTED") || !strings.Contains(buf.String(), "[HIGH  ]") {
		t.Error(buf.String())
	}
}

func TestSanitizeControlChars(t *testing.T) {
	if got := Sanitize("a\x1b[31mb\nc"); got != `a\x1b[31mb\x0ac` {
		t.Errorf("Sanitize = %q", got)
	}
	in := input(t)
	in.Changes = []diff.Change{{Type: diff.Added, Category: "user", Severity: diff.Low, Message: "user x\x1b[2J added"}}
	var buf bytes.Buffer
	WriteText(&buf, in)
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("escape sequence leaked to terminal: %q", buf.String())
	}
}

// End to end: hostile names/comments flow from real files through snapshot,
// diff and the HTML report and must come out escaped.
func TestHostileContentEscapedEndToEnd(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	base, _ := snapshot.Collect(snapshot.Options{Root: root})
	fixture.Write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+
		"<script>alert(1)</script>:x:1005:1005:\"><img src=x onerror=alert(2)>:/home/evil:/bin/bash\n", 0o644)
	fixture.Write(t, root, "home/evil/.ssh/authorized_keys",
		`command="\"><script>alert(3)</script>" ssh-ed25519 `+fixture.MalBlob+` </td><script>alert('4')</script> "q"`+"\n", 0o600)
	fixture.Write(t, root, "etc/sudoers.d/zz", `evil ALL=(ALL) NOPASSWD: ALL # <script>alert(5)</script>`+"\n", 0o440)
	fixture.Write(t, root, `usr/bin/x"><script>alert(6)</script>`, "x", 0o4755)
	cur, _ := snapshot.Collect(snapshot.Options{Root: root})
	cur.Hostname = `<script>alert(7)</script>`
	in := Input{Base: base, Current: cur, Changes: diff.Compare(base, cur), ToolVersion: "test"}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, in); err != nil {
		t.Fatal(err)
	}
	h := buf.String()
	for _, bad := range []string{"<script", "<img", "onerror=alert(2)>"} {
		if strings.Contains(h, bad) {
			t.Errorf("unescaped %q in report", bad)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(3)") {
		t.Error("hostile key option should appear, escaped")
	}
}
