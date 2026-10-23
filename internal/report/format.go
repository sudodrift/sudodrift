package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/permdrift/permdrift/internal/diff"
	"github.com/permdrift/permdrift/internal/snapshot"
)

// JSONVersion is the version of the JSON layout written by WriteJSON. It is
// bumped when a field is removed or changes meaning. Adding fields does not
// bump it.
const JSONVersion = 1

// Formats lists the output formats accepted by `permdrift diff --format`.
var Formats = []string{"text", "json", "csv"}

// ValidFormat reports whether f is one of Formats.
func ValidFormat(f string) bool {
	for _, k := range Formats {
		if k == f {
			return true
		}
	}
	return false
}

type jsonSnapshot struct {
	Hostname    string `json:"hostname"`
	Timestamp   string `json:"timestamp"`
	ContentHash string `json:"content_hash"`
	Warnings    int    `json:"warnings"`
}

type jsonSummary struct {
	Total      int            `json:"total"`
	Added      int            `json:"added"`
	Removed    int            `json:"removed"`
	Changed    int            `json:"changed"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	ByCategory map[string]int `json:"by_category"`
}

type jsonDoc struct {
	Version     int           `json:"version"`
	Tool        string        `json:"tool"`
	ToolVersion string        `json:"tool_version"`
	Base        jsonSnapshot  `json:"base"`
	Current     jsonSnapshot  `json:"current"`
	Ignored     int           `json:"ignored"`
	Summary     jsonSummary   `json:"summary"`
	Changes     []diff.Change `json:"changes"`
}

func jsonSnap(s *snapshot.Snapshot) jsonSnapshot {
	return jsonSnapshot{Hostname: s.Hostname, Timestamp: s.Timestamp, ContentHash: s.ContentHash, Warnings: len(s.Warnings)}
}

// WriteJSON writes the diff as one indented JSON document with a version
// field, a summary and the list of changes. The changes list is never null.
// Key order is fixed by the struct layout and map keys are sorted, so the
// same input gives the same bytes.
func WriteJSON(w io.Writer, in Input) error {
	s := diff.Summarize(in.Changes)
	changes := in.Changes
	if changes == nil {
		changes = []diff.Change{}
	}
	doc := jsonDoc{
		Version:     JSONVersion,
		Tool:        "permdrift",
		ToolVersion: in.ToolVersion,
		Base:        jsonSnap(in.Base),
		Current:     jsonSnap(in.Current),
		Ignored:     in.Ignored,
		Summary: jsonSummary{
			Total: s.Total, Added: s.Added, Removed: s.Removed, Changed: s.Changed,
			High: s.High, Medium: s.Medium, Low: s.Low, ByCategory: s.ByCategory,
		},
		Changes: changes,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// CSVHeader is the first row of the CSV output.
var CSVHeader = []string{"severity", "type", "category", "subject", "message"}

// CSVSafe makes a cell safe to open in a spreadsheet. A cell that starts with
// = + - @ (or a tab or carriage return, which some programs also treat as a
// formula start) gets a single quote in front, so it is read as text and not
// as a formula. The cell is otherwise unchanged. encoding/csv still does the
// quoting of commas, quotes and newlines.
func CSVSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// WriteCSV writes a header row and one row per change.
func WriteCSV(w io.Writer, in Input) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, c := range in.Changes {
		row := []string{c.Severity.String(), c.Type, c.Category, c.Subject, c.Message}
		for i := range row {
			row[i] = CSVSafe(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Write renders the diff in the named format (text, json or csv).
func Write(w io.Writer, format string, in Input) error {
	switch format {
	case "", "text":
		WriteText(w, in)
		return nil
	case "json":
		return WriteJSON(w, in)
	case "csv":
		return WriteCSV(w, in)
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}
