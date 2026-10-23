package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sudodrift/sudodrift/internal/fixture"
)

func collect(t *testing.T, root string, home bool) *Snapshot {
	t.Helper()
	s, err := Collect(Options{Root: root, IncludeHome: home, ToolVersion: "test",
		Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCollectFakeRoot(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	s := collect(t, root, false)

	if s.Hostname != "demo-host" || s.Timestamp != "2026-01-02T03:04:05Z" || s.ToolVersion != "test" {
		t.Errorf("metadata wrong: %+v", s)
	}
	if len(s.Users) != 4 {
		t.Fatalf("users=%d want 4", len(s.Users))
	}
	byName := map[string]User{}
	for _, u := range s.Users {
		byName[u.Name] = u
	}
	if u := byName["root"]; u.UID != 0 || !u.LoginShell || u.PasswordState != "locked" {
		t.Errorf("root parsed wrong: %+v", u)
	}
	if byName["daemon"].LoginShell {
		t.Error("daemon should not have a login shell")
	}
	if byName["alice"].PasswordState != "set" {
		t.Errorf("alice password state = %q", byName["alice"].PasswordState)
	}

	var sudo *Group
	for i := range s.Groups {
		if s.Groups[i].Name == "sudo" {
			sudo = &s.Groups[i]
		}
	}
	if sudo == nil || !sudo.Privileged || len(sudo.Members) != 1 || sudo.Members[0] != "alice" {
		t.Errorf("sudo group wrong: %+v", sudo)
	}

	if len(s.AuthorizedKeys) != 1 {
		t.Fatalf("keys=%d want 1", len(s.AuthorizedKeys))
	}
	k := s.AuthorizedKeys[0]
	if k.User != "alice" || k.Type != "ssh-ed25519" || k.Fingerprint != fixture.AliceFP || k.Comment != "alice@laptop" {
		t.Errorf("key wrong: %+v", k)
	}

	var rules, includes int
	for _, l := range s.Sudoers {
		switch l.Kind {
		case "rule":
			rules++
			if !l.RunAsAll {
				t.Errorf("expected RunAsAll on %q", l.Line)
			}
		case "include":
			includes++
		}
	}
	if rules != 2 || includes != 1 {
		t.Errorf("sudoers rules=%d includes=%d (lines: %+v)", rules, includes, s.Sudoers)
	}

	paths := map[string]FileEntry{}
	for _, f := range s.SUIDFiles {
		paths[f.Path] = f
	}
	if f, ok := paths["/usr/bin/sudo"]; !ok || f.Mode != "4755" || f.SHA256 == "" {
		t.Errorf("sudo SUID entry wrong: %+v", f)
	}
	if f, ok := paths["/usr/bin/wall"]; !ok || f.Mode != "2755" {
		t.Errorf("wall SGID entry wrong: %+v", f)
	}
	if _, ok := paths["/usr/bin/foo"]; ok {
		t.Error("foo is not SUID yet")
	}

	sens := map[string]FileEntry{}
	for _, f := range s.Sensitive {
		sens[f.Path] = f
	}
	for _, p := range []string{"/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/home/alice/.ssh", "/home/alice/.ssh/authorized_keys"} {
		if _, ok := sens[p]; !ok {
			t.Errorf("sensitive file %s missing", p)
		}
	}
	if sens["/etc/shadow"].Mode != "0640" {
		t.Errorf("shadow mode = %s", sens["/etc/shadow"].Mode)
	}
	if s.SSHDConfig["permitrootlogin"] != "no" {
		t.Errorf("sshd config: %+v", s.SSHDConfig)
	}
}

func TestHomeSkippedUnlessFlag(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	fixture.Write(t, root, "home/alice/evil", "x", 0o4755)
	fixture.Chmod(t, root, "home/alice/evil", 0o4777)
	for _, f := range collect(t, root, false).SUIDFiles {
		if f.Path == "/home/alice/evil" {
			t.Fatal("/home must be skipped by default")
		}
	}
	s := collect(t, root, true)
	var suid, ww bool
	for _, f := range s.SUIDFiles {
		suid = suid || f.Path == "/home/alice/evil"
	}
	for _, f := range s.WorldWritable {
		ww = ww || f.Path == "/home/alice/evil"
	}
	if !suid || !ww {
		t.Errorf("--include-home should find SUID (%v) and world-writable (%v)", suid, ww)
	}
}

func TestWorldWritableKeyDirs(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	fixture.Write(t, root, "etc/ww.conf", "x", 0o666)
	fixture.Write(t, root, "opt/ignored", "x", 0o666) // not a key dir
	s := collect(t, root, false)
	if len(s.WorldWritable) != 1 || s.WorldWritable[0].Path != "/etc/ww.conf" {
		t.Errorf("world-writable = %+v", s.WorldWritable)
	}
}

func TestHashStableAndSensitive(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	a := collect(t, root, false)
	b, _ := Collect(Options{Root: root, ToolVersion: "other"}) // different timestamp/version
	if a.ContentHash != b.ContentHash {
		t.Error("hash must ignore timestamp and tool version")
	}
	fixture.Chmod(t, root, "etc/shadow", 0o644)
	if c := collect(t, root, false); c.ContentHash == a.ContentHash {
		t.Error("hash must change when content changes")
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	k, ok, _ := ParseAuthorizedKey(`command="echo hi there",no-pty ssh-ed25519 ` + fixture.BobBlob + ` bob at host`)
	if !ok || k.Fingerprint != fixture.BobFP || k.Comment != "bob at host" || k.Options != `command="echo hi there",no-pty` {
		t.Errorf("parsed wrong: %+v ok=%v", k, ok)
	}
	if _, ok, e := ParseAuthorizedKey("# comment"); ok || e != "" {
		t.Error("comment should be silently skipped")
	}
	if _, ok, e := ParseAuthorizedKey("ssh-rsa !!!notbase64"); ok || e == "" {
		t.Error("bad base64 should produce an error message")
	}
}

func TestParseSudoLine(t *testing.T) {
	cases := []struct {
		in           string
		ok           bool
		kind         string
		nopasswd, aa bool
	}{
		{"# comment", false, "", false, false},
		{"", false, "", false, false},
		{"Defaults env_reset", true, "defaults", false, false},
		{"Defaults !authenticate", true, "defaults", true, false},
		{"alice ALL=(ALL) NOPASSWD: ALL", true, "rule", true, true},
		{"%admin ALL = (ALL:ALL) ALL", true, "rule", false, true},
		{"bob ALL=(root) /usr/bin/systemctl restart nginx", true, "rule", false, false},
		{"carol ALL = NOPASSWD: ALL", true, "rule", true, true},
		{"Cmnd_Alias X = /bin/ls", true, "alias", false, false},
		{"#includedir /etc/sudoers.d", true, "include", false, false},
	}
	for _, c := range cases {
		sl, ok := ParseSudoLine(c.in)
		if ok != c.ok {
			t.Errorf("%q ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (sl.Kind != c.kind || sl.NoPasswd != c.nopasswd || sl.RunAsAll != c.aa) {
			t.Errorf("%q -> %+v", c.in, sl)
		}
	}
	got := JoinContinuations([]string{"alice ALL=(ALL) \\", "  NOPASSWD: ALL", "next"})
	if len(got) != 2 || got[0] != "alice ALL=(ALL)    NOPASSWD: ALL" {
		t.Errorf("continuations: %q", got)
	}
}

func TestMissingRootFails(t *testing.T) {
	if _, err := Collect(Options{Root: "/definitely/not/here"}); err == nil {
		t.Error("expected error for missing root")
	}
}

func TestSymlinkCannotEscapeFakeRoot(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	// absolute link to the *host's* file must be re-rooted, not followed
	if err := os.Remove(filepath.Join(root, "etc/group")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc/group")); err != nil {
		t.Fatal(err)
	}
	s := collect(t, root, false)
	for _, g := range s.Groups {
		if g.GID == 0 && g.Name != "root" {
			t.Fatalf("read host file through symlink: %+v", g)
		}
	}
	// relative link inside the root still works
	if err := os.Remove(filepath.Join(root, "etc/group")); err != nil {
		t.Fatal(err)
	}
	fixture.Write(t, root, "etc/real-group", "root:x:0:\nsudo:x:27:alice\n", 0o644)
	if err := os.Symlink("real-group", filepath.Join(root, "etc/group")); err != nil {
		t.Fatal(err)
	}
	if s := collect(t, root, false); len(s.Groups) != 2 {
		t.Errorf("relative symlink inside root not followed: %d groups", len(s.Groups))
	}
}

func TestSymlinkLoopsTerminate(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	os.Symlink("loop2", filepath.Join(root, "usr/loop1"))
	os.Symlink("loop1", filepath.Join(root, "usr/loop2"))
	os.Symlink(".", filepath.Join(root, "usr/self"))
	os.Remove(filepath.Join(root, "etc/group"))
	os.Symlink("group", filepath.Join(root, "etc/group")) // self-loop on a file we read
	s := collect(t, root, false)
	if len(s.Users) != 4 {
		t.Errorf("users=%d", len(s.Users))
	}
}

func TestEmptySectionsSerialiseAsArrays(t *testing.T) {
	s := collect(t, t.TempDir(), false)
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), ":null") {
		t.Errorf("empty sections must be [] not null: %s", b)
	}
}

func TestUnreadableFilesWarnWithLogicalPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	root := t.TempDir()
	fixture.Base(t, root)
	if err := os.Chmod(filepath.Join(root, "home/alice/.ssh/authorized_keys"), 0); err != nil {
		t.Fatal(err)
	}
	s := collect(t, root, false)
	var found bool
	for _, w := range s.Warnings {
		if strings.Contains(w, root) {
			t.Errorf("warning leaks fake-root location: %q", w)
		}
		if strings.Contains(w, "/home/alice/.ssh/authorized_keys") {
			found = true
		}
	}
	if !found {
		t.Errorf("unreadable authorized_keys should produce a warning, got %v", s.Warnings)
	}
}

func TestEmptyAndMalformedInputs(t *testing.T) {
	root := t.TempDir()
	fixture.Base(t, root)
	fixture.Write(t, root, "home/alice/.ssh/authorized_keys", "", 0o600)
	fixture.Write(t, root, "home/bob/.ssh/authorized_keys", "# only a comment\n\nnot a key\nssh-ed25519 !!!notbase64 x\n", 0o600)
	fixture.Write(t, root, "etc/sudoers.d/bad", "this is ((( malformed\nbob ALL=(ALL\n\\\n", 0o440)
	s := collect(t, root, false)
	if len(s.AuthorizedKeys) != 0 {
		t.Errorf("keys=%v", s.AuthorizedKeys)
	}
	if len(s.Warnings) < 2 {
		t.Errorf("malformed key lines should warn: %v", s.Warnings)
	}
}
