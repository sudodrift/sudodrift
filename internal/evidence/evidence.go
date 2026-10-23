// Package evidence builds a review bundle from two snapshots: the inputs,
// the diff in text and JSON, an HTML report, a checksum manifest and a
// review template. It gathers material for a human reviewer. It does not
// sign anything and does not make the host compliant with anything.
package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/permdrift/permdrift/internal/diff"
	"github.com/permdrift/permdrift/internal/report"
)

// File names inside a bundle.
const (
	BaseFile     = "base.json"
	CurrentFile  = "current.json"
	DiffText     = "diff.txt"
	DiffJSON     = "diff.json"
	HTMLFile     = "report.html"
	ReviewFile   = "REVIEW.md"
	MetadataFile = "metadata.json"
	ManifestFile = "MANIFEST.sha256"
)

// MetadataVersion is the version of metadata.json.
const MetadataVersion = 1

// Input is what Build needs.
type Input struct {
	Report     report.Input // parsed snapshots and the filtered changes
	BaseRaw    []byte       // the base snapshot file exactly as read
	CurrentRaw []byte       // the current snapshot file exactly as read
	BaseName   string       // file name of the base input (no directory)
	CurName    string       // file name of the current input (no directory)
	MinSev     diff.Severity
	IgnoreFile string // base name of the ignore file, "" if none
	Now        time.Time
}

// File is one entry of a bundle.
type File struct {
	Name string
	Data []byte
}

// Metadata is written to metadata.json.
type Metadata struct {
	Version     int          `json:"version"`
	Tool        string       `json:"tool"`
	ToolVersion string       `json:"tool_version"`
	GeneratedAt string       `json:"generated_at"`
	Base        MetaSnapshot `json:"base"`
	Current     MetaSnapshot `json:"current"`
	MinSeverity string       `json:"min_severity"`
	IgnoreFile  string       `json:"ignore_file,omitempty"`
	Ignored     int          `json:"ignored"`
	Total       int          `json:"total_changes"`
	High        int          `json:"high"`
	Medium      int          `json:"medium"`
	Low         int          `json:"low"`
	Note        string       `json:"note"`
}

// MetaSnapshot describes one input snapshot.
type MetaSnapshot struct {
	InputName   string `json:"input_name"`
	Hostname    string `json:"hostname"`
	Timestamp   string `json:"timestamp"`
	ToolVersion string `json:"tool_version"`
	ContentHash string `json:"content_hash"`
	Warnings    int    `json:"warnings"`
}

const metaNote = "Evidence gathering aid. Not a signature, attestation or compliance statement."

// Build renders every file of the bundle in memory. MANIFEST.sha256 is last
// and lists every other file.
func Build(in Input) ([]File, error) {
	if in.Report.Base == nil || in.Report.Current == nil {
		return nil, errors.New("evidence: both snapshots are required")
	}
	rp := in.Report
	rp.Generated = in.Now

	var text, js, html bytes.Buffer
	report.WriteText(&text, rp)
	if err := report.WriteJSON(&js, rp); err != nil {
		return nil, err
	}
	if err := report.WriteHTML(&html, rp); err != nil {
		return nil, err
	}

	sum := diff.Summarize(rp.Changes)
	meta := Metadata{
		Version:     MetadataVersion,
		Tool:        "permdrift",
		ToolVersion: rp.ToolVersion,
		GeneratedAt: in.Now.UTC().Format(time.RFC3339),
		Base:        metaSnap(in.BaseName, rp.Base.Hostname, rp.Base.Timestamp, rp.Base.ToolVersion, rp.Base.ContentHash, len(rp.Base.Warnings)),
		Current:     metaSnap(in.CurName, rp.Current.Hostname, rp.Current.Timestamp, rp.Current.ToolVersion, rp.Current.ContentHash, len(rp.Current.Warnings)),
		MinSeverity: strings.ToLower(in.MinSev.String()),
		IgnoreFile:  in.IgnoreFile,
		Ignored:     rp.Ignored,
		Total:       sum.Total, High: sum.High, Medium: sum.Medium, Low: sum.Low,
		Note: metaNote,
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}

	files := []File{
		{BaseFile, in.BaseRaw},
		{CurrentFile, in.CurrentRaw},
		{DiffText, text.Bytes()},
		{DiffJSON, js.Bytes()},
		{HTMLFile, html.Bytes()},
		{ReviewFile, []byte(Review(rp, in.Now))},
		{MetadataFile, append(mb, '\n')},
	}
	files = append(files, File{ManifestFile, Manifest(files)})
	return files, nil
}

func metaSnap(name, host, ts, ver, hash string, warns int) MetaSnapshot {
	return MetaSnapshot{InputName: name, Hostname: host, Timestamp: ts, ToolVersion: ver, ContentHash: hash, Warnings: warns}
}

// Manifest returns sha256sum-compatible text ("hash  name") for files, sorted
// by name. Run `sha256sum -c MANIFEST.sha256` inside the bundle to verify it.
func Manifest(files []File) []byte {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b bytes.Buffer
	for _, f := range sorted {
		h := sha256.Sum256(f.Data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h[:]), f.Name)
	}
	return b.Bytes()
}

// Review renders REVIEW.md: a blank form with one entry per High finding.
func Review(in report.Input, now time.Time) string {
	sum := diff.Summarize(in.Changes)
	var b strings.Builder
	b.WriteString("# Access drift review\n\n")
	b.WriteString("This file is a template. Fill it in by hand. permdrift does not review anything itself.\n\n")
	fmt.Fprintf(&b, "- Host: %s\n", mdEscape(in.Current.Hostname))
	fmt.Fprintf(&b, "- Base snapshot taken: %s\n", mdEscape(in.Base.Timestamp))
	fmt.Fprintf(&b, "- Current snapshot taken: %s\n", mdEscape(in.Current.Timestamp))
	fmt.Fprintf(&b, "- Bundle generated: %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Changes: %d total (%d high, %d medium, %d low)\n\n", sum.Total, sum.High, sum.Medium, sum.Low)
	b.WriteString("Reviewer name:\n\nReview date:\n\n")
	b.WriteString("## High findings\n\n")
	n := 0
	for _, c := range in.Changes {
		if c.Severity != diff.High {
			continue
		}
		n++
		fmt.Fprintf(&b, "### H%d. %s\n\n", n, mdEscape(report.Sanitize(c.Message)))
		fmt.Fprintf(&b, "- Category: %s, %s\n", mdEscape(c.Category), mdEscape(c.Type))
		b.WriteString("- Decision: [ ] approved  [ ] not approved\n")
		b.WriteString("- Notes:\n\n")
	}
	if n == 0 {
		b.WriteString("No high findings in this diff.\n\n")
	}
	b.WriteString("## Other changes\n\n")
	fmt.Fprintf(&b, "%d medium and %d low change(s) are listed in diff.txt and report.html. Add notes here if you looked at them.\n\n", sum.Medium, sum.Low)
	b.WriteString("Notes:\n\n")
	b.WriteString("## Limits\n\n")
	b.WriteString("The snapshots are plain files. Nothing in this bundle is signed, and MANIFEST.sha256 only shows that the files were not changed after it was written. Severity is a heuristic.\n")
	return b.String()
}

var mdSpecial = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", "&lt;", ">", "&gt;", "#", `\#`, "|", `\|`, "!", `\!`, "&", "&amp;",
)

func mdEscape(s string) string {
	return mdSpecial.Replace(report.Sanitize(s))
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// SafeName turns a hostname into something safe for a file name: only
// letters, digits, dot, underscore and hyphen, no leading dot, at most 64
// bytes.
func SafeName(s string) string {
	s = unsafeName.ReplaceAllString(s, "_")
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	s = strings.TrimLeft(s, ".")
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// DefaultName is evidence-<host>-<date>.zip.
func DefaultName(host string, now time.Time) string {
	return fmt.Sprintf("evidence-%s-%s.zip", SafeName(host), now.UTC().Format("2006-01-02"))
}

// WriteZip writes files into a new zip at path, all under one top-level
// folder named after the zip file. It refuses to replace an existing file
// unless force is set. The zip is written to a temporary file first.
func WriteZip(path string, files []File, now time.Time, force bool) error {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to replace it)", path)
		}
	}
	top := strings.TrimSuffix(filepath.Base(path), ".zip")
	top = SafeName(top)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".permdrift-evidence-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	zw := zip.NewWriter(tmp)
	for _, f := range files {
		h := &zip.FileHeader{Name: top + "/" + f.Name, Method: zip.Deflate, Modified: now.UTC()}
		h.SetMode(0o600)
		w, err := zw.CreateHeader(h)
		if err != nil {
			tmp.Close()
			return err
		}
		if _, err := w.Write(f.Data); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteDir writes files into dir. The directory must not exist or must be
// empty, so a bundle never mixes with other files.
func WriteDir(dir string, files []File) error {
	if ents, err := os.ReadDir(dir); err == nil {
		if len(ents) > 0 {
			return fmt.Errorf("%s is not empty", dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
