package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const fixtures = "../../internal/sudors/testdata/"

func TestSudorsCheckExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"sudors-check", "--root", fixtures + "clean"}, 0},
		{[]string{"sudors-check", "--root", fixtures + "clean", "--fail-on", "info"}, 1},
		{[]string{"sudors-check", "--root", fixtures + "commands"}, 1},
		{[]string{"sudors-check", "--root", fixtures + "tags", "--fail-on", "differs"}, 1},
		// 25.10 compares wildcard arguments literally: "differs", not "breaks"
		{[]string{"sudors-check", "--root", fixtures + "includes", "--target", "ubuntu-25.10", "--fail-on", "breaks"}, 1},
		{[]string{"sudors-check", "--root", fixtures + "args", "--target", "ubuntu-25.10"}, 1},
		{[]string{"sudors-check", "--root", fixtures + "not-included"}, 0},
		{[]string{"sudors-check", "--root", fixtures + "clean", "--format", "xml"}, 2},
		{[]string{"sudors-check", "--root", fixtures + "clean", "--target", "ubuntu-24.04"}, 2},
		{[]string{"sudors-check", "--root", fixtures + "clean", "--fail-on", "high"}, 2},
		{[]string{"sudors-check", "--root", fixtures + "does-not-exist"}, 2},
		{[]string{"sudors-check", "extra"}, 2},
		{[]string{"sudors-check", "--bogus"}, 2},
	}
	for _, tc := range cases {
		if c, out, errOut := runCLI(tc.args...); c != tc.code {
			t.Errorf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", tc.args, c, tc.code, out, errOut)
		}
	}
}

func TestSudorsCheckJSON(t *testing.T) {
	c, out, _ := runCLI("sudors-check", "--root", fixtures+"users-hosts", "--format", "json")
	if c != 1 {
		t.Fatalf("exit %d", c)
	}
	var r struct {
		Target   string         `json:"target"`
		SudoRS   string         `json:"sudo_rs_version"`
		Summary  map[string]int `json:"summary"`
		Findings []struct {
			Severity, File, Rule, Explanation, Fix, Source string
			Line                                           int
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if r.Target != "ubuntu-26.04" || r.SudoRS != "0.2.13" || r.Summary["breaks"] != 9 || r.Summary["differs"] != 2 {
		t.Errorf("unexpected summary: %+v", r)
	}
	f := r.Findings[0]
	if f.Severity != "breaks" || f.File != "/etc/sudoers" || f.Line != 2 || f.Rule != "netgroup" || f.Fix == "" || !strings.HasPrefix(f.Source, "https://") {
		t.Errorf("unexpected first finding: %+v", f)
	}
}

func TestSudorsCheckText(t *testing.T) {
	_, out, _ := runCLI("sudors-check", "--root", fixtures+"syntax")
	for _, s := range []string{"BREAKS   /etc/sudoers:3  [continuation-in-command]", "line:   #1000 ALL = /bin/rm /tmp/cache.tmp", "Summary: 2 breaks, 0 differs, 0 info"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in:\n%s", s, out)
		}
	}
}
