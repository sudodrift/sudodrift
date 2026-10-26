package sudors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func keys(r *Result) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, fmt.Sprintf("%s %s:%d %s", f.Severity, f.File, f.Line, f.Rule))
	}
	return out
}

func mustTarget(t *testing.T, name string) Target {
	t.Helper()
	tg, err := FindTarget(name)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// Every fixture and the exact findings expected for Ubuntu 26.04
// (sudo-rs 0.2.13). scripts/check-sudors-fixtures.py compares the "breaks"
// lines with visudo -c from a real sudo-rs build.
var want2604 = map[string][]string{
	"args": {
		"breaks /etc/sudoers:2 arg-wildcard",
		"differs /etc/sudoers:4 arg-charclass",
		"breaks /etc/sudoers:5 arg-wildcard",
		"breaks /etc/sudoers:6 regex",
		"breaks /etc/sudoers:7 illegal-escape",
		"info /etc/sudoers:8 sudoedit-files",
	},
	"clean": {
		"info /etc/sudoers:9 defaults-ignored",
		"info /etc/sudoers:10 defaults-ignored",
	},
	"commands": {
		"breaks /etc/sudoers:2 regex",
		"breaks /etc/sudoers:3 digest",
		"breaks /etc/sudoers:4 arg-wildcard",
	},
	"defaults": {
		"breaks /etc/sudoers:2 defaults-unknown",
		"breaks /etc/sudoers:3 defaults-unknown",
		"differs /etc/sudoers:4 defaults-ignored",
		"breaks /etc/sudoers:5 defaults-unknown",
		"differs /etc/sudoers:6 defaults-ignored",
		"differs /etc/sudoers:7 defaults-ignored",
		"breaks /etc/sudoers:8 defaults-invalid",
		"breaks /etc/sudoers:9 defaults-invalid",
		"breaks /etc/sudoers:10 defaults-invalid",
		"breaks /etc/sudoers:11 defaults-invalid",
		"differs /etc/sudoers:12 defaults-ignored",
		"differs /etc/sudoers:13 defaults-ignored",
		"info /etc/sudoers:14 defaults-ignored",
		"differs /etc/sudoers:16 defaults-ignored",
		"breaks /etc/sudoers:17 defaults-unknown",
		"breaks /etc/sudoers:18 defaults-unknown",
	},
	"includes": {
		"breaks /etc/sudoers:4 includedir-percent-h",
		"info /etc/sudoers:5 include-missing",
		"breaks /etc/local/extra:1 arg-wildcard",
		"breaks /etc/sudoers.d/10-ops:2 option-unsupported",
	},
	"not-included": {
		"info /etc/sudoers.d/orphan:0 not-included",
	},
	"sudoers-rs": {
		"info /etc/sudoers-rs:0 sudoers-rs-file",
		"breaks /etc/sudoers-rs:2 defaults-unknown",
	},
	"syntax": {
		"breaks /etc/sudoers:3 continuation-in-command",
		"breaks /etc/sudoers:10 tab-in-command",
	},
	"tags": {
		"breaks /etc/sudoers:2 tag-unsupported",
		"differs /etc/sudoers:3 tag-ignored",
		"differs /etc/sudoers:3 tag-ignored",
		"breaks /etc/sudoers:5 option-unsupported",
		"breaks /etc/sudoers:6 option-unsupported",
		"breaks /etc/sudoers:6 option-unsupported",
		"breaks /etc/sudoers:7 option-unsupported",
		"breaks /etc/sudoers:8 option-unsupported",
		"differs /etc/sudoers:10 tag-ignored",
	},
	"users-hosts": {
		"breaks /etc/sudoers:2 netgroup",
		"differs /etc/sudoers:3 nonunix-group",
		"breaks /etc/sudoers:4 host-wildcard",
		"breaks /etc/sudoers:5 host-address",
		"breaks /etc/sudoers:6 host-address",
		"breaks /etc/sudoers:7 host-address",
		"breaks /etc/sudoers:8 netgroup",
		"breaks /etc/sudoers:9 host-address",
		"breaks /etc/sudoers:10 netgroup",
		"differs /etc/sudoers:11 nonunix-group",
		"breaks /etc/sudoers:13 host-wildcard",
	},
	"utf8": {
		"breaks /etc/sudoers:2 not-utf8",
	},
}

func TestFixtures2604(t *testing.T) {
	dirs, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != len(want2604) {
		t.Errorf("%d fixture dirs but %d expectations; keep them in sync", len(dirs), len(want2604))
	}
	tg := mustTarget(t, "ubuntu-26.04")
	for name, want := range want2604 {
		t.Run(name, func(t *testing.T) {
			r, err := Check(filepath.Join("testdata", name), tg)
			if err != nil {
				t.Fatal(err)
			}
			if got := keys(r); !reflect.DeepEqual(got, want) {
				t.Errorf("findings differ\n got: %q\nwant: %q", got, want)
			}
			for _, f := range r.Findings {
				if f.Explanation == "" || f.Fix == "" || !strings.HasPrefix(f.Source, "https://") {
					t.Errorf("finding %s:%d %s lacks explanation, fix or source", f.File, f.Line, f.Rule)
				}
			}
		})
	}
}

// Ubuntu 25.10 is based on sudo-rs 0.2.8, which compared arguments literally
// instead of rejecting wildcards, and had lecture as a flag.
func TestTarget2510(t *testing.T) {
	tg := mustTarget(t, "ubuntu-25.10")
	cases := map[string][]string{
		"args": {
			"differs /etc/sudoers:2 arg-wildcard",
			"differs /etc/sudoers:3 arg-wildcard",
			"differs /etc/sudoers:4 arg-charclass",
			"differs /etc/sudoers:5 arg-wildcard",
			"differs /etc/sudoers:6 regex",
			"breaks /etc/sudoers:7 illegal-escape",
			"info /etc/sudoers:8 sudoedit-files",
			"differs /etc/sudoers:10 arg-wildcard",
		},
		"users-hosts": {
			"breaks /etc/sudoers:2 netgroup",
			"breaks /etc/sudoers:3 user-escaped-space",
			"breaks /etc/sudoers:4 host-wildcard",
			"differs /etc/sudoers:5 host-address",
			"breaks /etc/sudoers:6 host-address",
			"breaks /etc/sudoers:7 host-address",
			"breaks /etc/sudoers:8 netgroup",
			"differs /etc/sudoers:9 host-address",
			"breaks /etc/sudoers:10 netgroup",
			"differs /etc/sudoers:11 nonunix-group",
			"breaks /etc/sudoers:13 host-wildcard",
		},
	}
	for name, want := range cases {
		r, err := Check(filepath.Join("testdata", name), tg)
		if err != nil {
			t.Fatal(err)
		}
		if got := keys(r); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: findings differ\n got: %q\nwant: %q", name, got, want)
		}
	}
	r, _ := Check("testdata/defaults", tg)
	if !contains(keys(r), "breaks /etc/sudoers:6 defaults-invalid") {
		t.Errorf("lecture=always should be rejected by 0.2.8 (lecture is a flag there): %q", keys(r))
	}
}

func TestTargetUpstream(t *testing.T) {
	r, err := Check("testdata/defaults", mustTarget(t, "upstream"))
	if err != nil {
		t.Fatal(err)
	}
	got := keys(r)
	// 0.2.15 knows timestamp_type but only tty and ppid.
	if !contains(got, "breaks /etc/sudoers:5 defaults-invalid") || contains(got, "breaks /etc/sudoers:5 defaults-unknown") {
		t.Errorf("timestamp_type=global: %q", got)
	}
	// 0.2.14 joins continuation lines inside commands and 0.2.15 accepts tabs.
	r, err = Check("testdata/syntax", mustTarget(t, "upstream"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("syntax fixture should be clean on 0.2.15: %q", keys(r))
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func writeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSingleLines(t *testing.T) {
	tg := mustTarget(t, "ubuntu-26.04")
	cases := []struct {
		line string
		want []string // rule names, in order
	}{
		{"%sudo ALL=(ALL:ALL) ALL", nil},
		{"alice ALL = (root) NOPASSWD: /usr/bin/systemctl restart nginx", nil},
		{"alice ALL = /usr/bin/fsck*", nil},
		{"alice ALL = /usr/sbin/service ntp *", nil},
		{"alice ALL = /usr/bin/passwd \"\"", nil},
		{"alice ALL = /usr/bin/printf a\\,b\\:c\\=d", nil},
		{"alice ALL = /bin/rm -rf /tmp/*", []string{"arg-wildcard"}},
		{"alice ALL = /bin/ls * -l", []string{"arg-wildcard"}},
		{"alice ALL = !/usr/bin/rm *.txt", []string{"arg-wildcard"}},
		{"alice ALL = /usr/bin/id, /bin/cat /etc/[a-z]*", []string{"arg-wildcard"}},
		{"alice ALL = sha224:abc,sha256:def /usr/bin/id", []string{"digest"}},
		{"alice ALL = NOPASSWD:INTERCEPT: /usr/bin/id", []string{"tag-unsupported"}},
		{"alice ALL = NOLOG_OUTPUT: /usr/bin/id", []string{"tag-ignored"}},
		{"alice ALL = NOFOLLOW: NOINTERCEPT: /usr/bin/id", nil},
		{"alice ALL = APPARMOR_PROFILE=unconfined /usr/bin/id", nil},
		{"alice ALL = LIMITPRIVS=basic /usr/bin/id", []string{"option-unsupported"}},
		{"alice web1 = /usr/bin/id : 192.168.0.1 = /usr/bin/uptime", []string{"host-address"}},
		{"alice ALL = (%:admins) /usr/bin/id", []string{"nonunix-group"}},
		{"Defaults:alice env_reset, requiretty", []string{"defaults-unknown"}},
		{"Defaults>root !insults", nil},
		{"Defaults!/usr/bin/id noexec", nil},
		{"Defaults!^/usr/bin/.*$ noexec", []string{"regex"}},
		{"Defaults timestamp_timeout=2.5, passwd_timeout=0", nil},
		{"Defaults umask=0077, !umask", nil},
		{"Defaults editor=/usr/bin/vi, !editor", []string{"defaults-invalid"}},
		{"Defaults env_check -= TZ", nil},
		{"Defaults noninteractive_auth", nil},
		{"Defaults runcwd=*", []string{"defaults-unknown"}},
		{"Defaults lecture=sometimes", []string{"defaults-invalid"}},
		{"Defaults verifypw=all", nil},
		{"Defaults !visiblepw, !insults, !fqdn, lecture=never", nil},
		{"Cmnd_Alias A = /usr/bin/id : B = /bin/rm *.log", []string{"arg-wildcard"}},
		{"Host_Alias H = *.lan", []string{"host-wildcard"}},
		{"User_Alias U = alice, bob", nil},
		{"#42 ALL = /bin/rm /tmp/?", []string{"arg-wildcard"}},
		{"alice ALL = /usr/bin/id # /bin/rm *.txt", nil},
	}
	for _, tc := range cases {
		root := writeRoot(t, map[string]string{"etc/sudoers": tc.line + "\n"})
		r, err := Check(root, tg)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range r.Findings {
			got = append(got, f.Rule)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got rules %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestIncludeLoopAndRelative(t *testing.T) {
	root := writeRoot(t, map[string]string{
		"etc/sudoers":       "@include sudoers.local\n",
		"etc/sudoers.local": "@include /etc/sudoers\n#include \"/etc/with space\"\n",
		"etc/with space":    "alice ALL = /bin/rm *.txt\n",
	})
	r, err := Check(root, mustTarget(t, "ubuntu-26.04"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/etc/sudoers", "/etc/sudoers.local", "/etc/with space"}; !reflect.DeepEqual(r.Files, want) {
		t.Errorf("files %q, want %q", r.Files, want)
	}
	if got := keys(r); !reflect.DeepEqual(got, []string{"breaks /etc/with space:1 arg-wildcard"}) {
		t.Errorf("findings %q", got)
	}
}

func TestMissingRoot(t *testing.T) {
	if _, err := Check(filepath.Join(t.TempDir(), "nope"), mustTarget(t, "ubuntu-26.04")); err == nil {
		t.Error("expected an error for a missing root")
	}
	if _, err := Check(t.TempDir(), mustTarget(t, "ubuntu-26.04")); err == nil {
		t.Error("expected an error when etc/sudoers is missing")
	}
}

func TestStripComment(t *testing.T) {
	cases := map[string]string{
		"a ALL = ALL # note":           "a ALL = ALL ",
		"#1000 ALL = ALL":              "#1000 ALL = ALL",
		"%#100 ALL = ALL #x":           "%#100 ALL = ALL ",
		`Defaults secure_path="/a#b"`:  `Defaults secure_path="/a#b"`,
		"#includedir /etc/sudoers.d":   "#includedir /etc/sudoers.d",
		`a ALL = /bin/echo \# # c`:     `a ALL = /bin/echo \# `,
		"# just a comment":             "",
		"   #include /etc/sudoers.loc": "   #include /etc/sudoers.loc",
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	w, bad := splitArgs(`/usr/bin/printf a\,b  c\ d \*`)
	if want := []string{"/usr/bin/printf", "a,b", "c d", "*"}; !reflect.DeepEqual(w, want) {
		t.Errorf("words %q, want %q", w, want)
	}
	if !reflect.DeepEqual(bad, []string{`\*`}) {
		t.Errorf("bad escapes %q", bad)
	}
}

func TestOutput(t *testing.T) {
	r, err := Check("testdata/commands", mustTarget(t, "ubuntu-26.04"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := Write(&b, "text", r); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"target ubuntu-26.04 (sudo-rs 0.2.13)", "BREAKS   /etc/sudoers:3  [digest]", "Summary: 3 breaks, 0 differs, 0 info"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("text output missing %q:\n%s", s, b.String())
		}
	}
	b.Reset()
	if err := Write(&b, "json", r); err != nil {
		t.Fatal(err)
	}
	var j struct {
		Version  int            `json:"version"`
		Summary  map[string]int `json:"summary"`
		Findings []struct {
			Severity string `json:"severity"`
			Line     int    `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j.Version != 1 || j.Summary["breaks"] != 3 || len(j.Findings) != 3 || j.Findings[0].Severity != "breaks" || j.Findings[0].Line != 2 {
		t.Errorf("unexpected JSON: %s", b.String())
	}
	if err := Write(&b, "xml", r); err == nil {
		t.Error("expected an error for an unknown format")
	}

	clean := &Result{Target: "x", SudoRS: "0.2.13", Files: []string{"/etc/sudoers"}, Findings: []Finding{}}
	b.Reset()
	_ = WriteText(&b, clean)
	if !strings.Contains(b.String(), "No findings.") {
		t.Errorf("clean output: %s", b.String())
	}
}

func TestParseSeverity(t *testing.T) {
	for s, want := range map[string]Severity{"breaks": Breaks, "Differs": Differs, " info ": Info} {
		got, err := ParseSeverity(s)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := ParseSeverity("high"); err == nil {
		t.Error("expected an error")
	}
	if _, err := FindTarget("ubuntu-24.04"); err == nil {
		t.Error("expected an error for an unknown target")
	}
}
