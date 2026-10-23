package diff

import (
	"os"
	"strings"
	"testing"

	"github.com/sudodrift/sudodrift/internal/fixture"
	"github.com/sudodrift/sudodrift/internal/ignore"
	"github.com/sudodrift/sudodrift/internal/snapshot"
)

func snap(t *testing.T, root string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.Collect(snapshot.Options{Root: root, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func find(cs []Change, substr string) *Change {
	for i := range cs {
		if strings.Contains(cs[i].Message, substr) {
			return &cs[i]
		}
	}
	return nil
}

// suidRootSev: SUID files owned by root are High; fixture files are owned by
// the user running the tests, so this is Medium unless tests run as root.
func suidRootSev() Severity {
	if os.Getuid() == 0 {
		return High
	}
	return Medium
}

func TestNoDrift(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	if cs := Compare(snap(t, root), snap(t, root)); len(cs) != 0 {
		t.Fatalf("expected no drift, got %+v", cs)
	}
}

func TestSemanticDiff(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	base := snap(t, root)
	fixture.Drift(t, root)
	cs := Compare(base, snap(t, root))

	want := []struct {
		substr string
		typ    string
		sev    Severity
	}{
		{"SSH key " + fixture.BobFP + " added for user bob", Added, High},   // bob is now in sudo
		{"SSH key " + fixture.MalFP + " added for user alice", Added, High}, // alice is in sudo
		{"NOPASSWD + ALL=(ALL) sudo rule added for bob", Added, High},
		{"user bob added to group sudo", Added, High},
		{"user mallory added to group docker", Added, High},
		{"user toor added (uid=0", Added, High},
		{"user mallory added (uid=1002", Added, Medium},
		{"/usr/bin/foo is now SUID", Added, suidRootSev()},
		{"/etc/cron.hourly/cleanup.sh is now world-writable", Added, High},
		{"/etc/shadow permissions loosened (secret now readable by group/others)", Changed, High},
		{"sshd_config permitrootlogin: \"no\" -> \"yes\"", Changed, High},
		{"sshd_config passwordauthentication: \"no\" -> \"yes\"", Changed, High},
		{"group mallory added", Added, Low},
	}
	for _, w := range want {
		c := find(cs, w.substr)
		if c == nil {
			t.Errorf("missing change containing %q", w.substr)
			continue
		}
		if c.Type != w.typ || c.Severity != w.sev {
			t.Errorf("%q: got type=%s sev=%s, want %s/%s", w.substr, c.Type, c.Severity, w.typ, w.sev)
		}
	}
	// sorted: severity must be non-increasing
	for i := 1; i < len(cs); i++ {
		if cs[i].Severity > cs[i-1].Severity {
			t.Fatalf("not sorted by severity at %d", i)
		}
	}
	// untouched SUID files produce nothing
	if c := find(cs, "/usr/bin/sudo"); c != nil {
		t.Errorf("unexpected change for sudo: %+v", c)
	}
}

func TestBecameSUIDAndRemovals(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	base := snap(t, root)
	// wall: SGID -> SUID+SGID ; sudo loses SUID; alice removed from sudo; key removed
	fixture.Chmod(t, root, "usr/bin/wall", 0o6755)
	fixture.Chmod(t, root, "usr/bin/sudo", 0o755)
	fixture.Write(t, root, "etc/group", "root:x:0:\nsudo:x:27:\ndocker:x:999:\nalice:x:1000:\nbob:x:1001:\n", 0o644)
	fixture.Write(t, root, "home/alice/.ssh/authorized_keys", "", 0o600)
	cs := Compare(base, snap(t, root))
	if c := find(cs, "/usr/bin/wall became SUID"); c == nil || c.Severity != High {
		t.Errorf("wall: %+v", c)
	}
	if c := find(cs, "/usr/bin/sudo no longer SUID"); c == nil || c.Severity != Low || c.Type != Removed {
		t.Errorf("sudo: %+v", c)
	}
	if c := find(cs, "user alice removed from group sudo"); c == nil || c.Severity != Low {
		t.Errorf("member removal: %+v", c)
	}
	if c := find(cs, "SSH key "+fixture.AliceFP+" removed"); c == nil || c.Type != Removed {
		t.Errorf("key removal: %+v", c)
	}
}

func TestSUIDContentChange(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	base := snap(t, root)
	fixture.Write(t, root, "usr/bin/sudo", "#!/bin/sh\nbackdoor\n", 0o4755)
	cs := Compare(base, snap(t, root))
	c := find(cs, "/usr/bin/sudo content changed")
	if c == nil || c.Severity != suidRootSev() {
		t.Errorf("content change: %+v", c)
	}
}

func TestFilterIgnoreAndMinSeverity(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	base := snap(t, root)
	fixture.Drift(t, root)
	cs := Compare(base, snap(t, root))

	m, _ := ignore.Parse(strings.NewReader("suid:/usr/bin/foo\nssh_key:bob:*\n"))
	kept, ign := Filter(cs, m, Low)
	if ign != 2 || len(kept) != len(cs)-2 {
		t.Errorf("ignored=%d kept=%d total=%d", ign, len(kept), len(cs))
	}
	if find(kept, "/usr/bin/foo") != nil {
		t.Error("foo should be ignored")
	}
	high, _ := Filter(cs, nil, High)
	for _, c := range high {
		if c.Severity != High {
			t.Errorf("min severity leak: %+v", c)
		}
	}
	s := Summarize(cs)
	if s.Total != len(cs) || s.High+s.Medium+s.Low != s.Total || s.Added+s.Removed+s.Changed != s.Total {
		t.Errorf("bad summary %+v", s)
	}
}

func TestParseSeverity(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Error("HIGH")
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("expected error")
	}
}
