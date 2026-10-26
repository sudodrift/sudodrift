package sudors

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Formats lists the supported output formats.
var Formats = []string{"text", "json"}

// Write prints r in the given format.
func Write(w io.Writer, format string, r *Result) error {
	switch format {
	case "", "text":
		return WriteText(w, r)
	case "json":
		return WriteJSON(w, r)
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}

// WriteText prints a human-readable report.
func WriteText(w io.Writer, r *Result) error {
	ew := &errWriter{w: w}
	ew.printf("sudo-rs readiness check, target %s (sudo-rs %s)\n", r.Target, r.SudoRS)
	ew.printf("Files read: %s\n\n", strings.Join(r.Files, ", "))
	if len(r.Findings) == 0 {
		ew.printf("No findings. Nothing in these files is known to behave differently under sudo-rs.\n")
		return ew.err
	}
	for _, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ew.printf("%-8s %s  [%s]\n", strings.ToUpper(f.Severity.String()), loc, f.Rule)
		if f.Text != "" {
			ew.printf("  line:   %s\n", f.Text)
		}
		ew.printf("  why:    %s\n", f.Explanation)
		ew.printf("  fix:    %s\n", f.Fix)
		ew.printf("  source: %s\n\n", f.Source)
	}
	ew.printf("Summary: %d breaks, %d differs, %d info\n", r.Count(Breaks), r.Count(Differs), r.Count(Info))
	return ew.err
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, a...)
	}
}

// JSONVersion is bumped when the JSON layout changes in a way that breaks
// readers.
const JSONVersion = 1

type jsonReport struct {
	Version  int            `json:"version"`
	Tool     string         `json:"tool"`
	Target   string         `json:"target"`
	SudoRS   string         `json:"sudo_rs_version"`
	Files    []string       `json:"files"`
	Summary  map[string]int `json:"summary"`
	Findings []Finding      `json:"findings"`
}

// WriteJSON prints r as indented JSON.
func WriteJSON(w io.Writer, r *Result) error {
	out := jsonReport{
		Version: JSONVersion, Tool: "sudodrift sudors-check", Target: r.Target, SudoRS: r.SudoRS, Files: r.Files,
		Summary:  map[string]int{"breaks": r.Count(Breaks), "differs": r.Count(Differs), "info": r.Count(Info)},
		Findings: r.Findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
