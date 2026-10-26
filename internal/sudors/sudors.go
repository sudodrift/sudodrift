// Package sudors reads a sudoers tree and reports lines that sudo-rs rejects,
// ignores or handles differently from original sudo.
package sudors

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity of a finding.
type Severity int

const (
	// Info marks something worth knowing that does not change behavior much.
	Info Severity = iota + 1
	// Differs marks a line that sudo-rs accepts but that does not work the
	// way it does in original sudo.
	Differs
	// Breaks marks a line that sudo-rs rejects. sudo-rs skips the whole line.
	Breaks
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Differs:
		return "differs"
	case Breaks:
		return "breaks"
	}
	return "unknown"
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity parses breaks|differs|info.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "differs":
		return Differs, nil
	case "breaks":
		return Breaks, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want breaks, differs or info)", s)
}

// Finding is one problem on one line.
type Finding struct {
	Severity    Severity `json:"severity"`
	Rule        string   `json:"rule"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Text        string   `json:"text,omitempty"`
	Explanation string   `json:"explanation"`
	Fix         string   `json:"fix"`
	Source      string   `json:"source"`
}

type version [3]int

func (v version) less(o version) bool {
	for i := range v {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false
}

func (v version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// Target is a sudo-rs release to check against.
type Target struct {
	Name    string
	Version version
	Note    string
}

// Targets lists the supported --target values.
var Targets = []Target{
	{Name: "ubuntu-26.04", Version: v0213, Note: "Ubuntu 26.04 LTS ships sudo-rs based on 0.2.13"},
	{Name: "ubuntu-25.10", Version: v028, Note: "Ubuntu 25.10 ships sudo-rs based on 0.2.8 with some later fixes backported"},
	{Name: "upstream", Version: v0215, Note: "sudo-rs 0.2.15, the newest upstream release checked"},
}

// DefaultTarget is used when no --target is given.
const DefaultTarget = "ubuntu-26.04"

// FindTarget looks up a target by name.
func FindTarget(name string) (Target, error) {
	var names []string
	for _, t := range Targets {
		if t.Name == name {
			return t, nil
		}
		names = append(names, t.Name)
	}
	return Target{}, fmt.Errorf("unknown target %q (want %s)", name, strings.Join(names, ", "))
}

// Result is the outcome of one check.
type Result struct {
	Target   string    `json:"target"`
	SudoRS   string    `json:"sudo_rs_version"`
	Files    []string  `json:"files"`
	Findings []Finding `json:"findings"`
}

// Count returns how many findings have exactly severity s.
func (r *Result) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Worst returns the highest severity found, or 0 when there are none.
func (r *Result) Worst() Severity {
	var w Severity
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

func sortFindings(fs []Finding, order map[string]int) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			oa, oka := order[a.File]
			ob, okb := order[b.File]
			if oka && okb {
				return oa < ob
			}
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}
