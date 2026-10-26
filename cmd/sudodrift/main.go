// sudodrift: Linux permission drift detector.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sudodrift/sudodrift/internal/diff"
	"github.com/sudodrift/sudodrift/internal/evidence"
	"github.com/sudodrift/sudodrift/internal/ignore"
	"github.com/sudodrift/sudodrift/internal/report"
	"github.com/sudodrift/sudodrift/internal/snapshot"
	"github.com/sudodrift/sudodrift/internal/sudors"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.4.0-dev"

const usage = `sudodrift ` + "%s" + `: Linux permission drift detector

Usage:
  sudodrift snapshot -o snap.json [--root /] [--include-home] [--exclude DIRS]
  sudodrift diff   base.json current.json [--format text|json|csv] [--ignore FILE] [--min-severity low|medium|high] [--fail-on low|medium|high]
  sudodrift report base.json current.json -o report.html [--ignore FILE] [--min-severity LEVEL]
  sudodrift evidence --base base.json --current now.json [-o FILE.zip | --dir DIR] [--ignore FILE] [--min-severity LEVEL] [--force]
  sudodrift sudors-check [--root DIR] [--format text|json] [--target ubuntu-26.04|ubuntu-25.10|upstream] [--fail-on breaks|differs|info]
  sudodrift version

Exit codes: 0 = no drift (or file written), 1 = drift found (diff), 2 = error.
sudors-check: 0 = nothing at the --fail-on level (default breaks), 1 = findings at that level, 2 = error.
`

func init() {
	// `go install ...@vX.Y.Z` has no -ldflags; fall back to the module version.
	if strings.HasSuffix(version, "-dev") {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "snapshot":
		err = cmdSnapshot(args[1:], stdout, stderr)
	case "diff":
		code, err = cmdDiff(args[1:], stdout, stderr)
	case "report":
		err = cmdReport(args[1:], stdout, stderr)
	case "evidence":
		err = cmdEvidence(args[1:], stdout, stderr)
	case "sudors-check":
		code, err = cmdSudorsCheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "sudodrift", version)
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version)
	default:
		fmt.Fprintf(stderr, "sudodrift: unknown command %q\n\n", args[0])
		fmt.Fprintf(stderr, usage, version)
		return 2
	}
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		if err == errUsage {
			return 2
		}
		fmt.Fprintln(stderr, "sudodrift:", err)
		return 2
	}
	return code
}

// parseInterspersed lets flags appear before, between or after positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// errUsage marks an error whose message (and usage text) the flag package has
// already printed, so run() only needs to set the exit code.
var errUsage = errors.New("usage error")

var usageLines = map[string]string{
	"snapshot":     "sudodrift snapshot [-o snap.json] [--root DIR] [--include-home] [--exclude DIRS]",
	"diff":         "sudodrift diff base.json current.json [--format text|json|csv] [--ignore FILE] [--min-severity low|medium|high] [--fail-on low|medium|high]",
	"evidence":     "sudodrift evidence --base base.json --current now.json [-o FILE.zip | --dir DIR] [--ignore FILE] [--min-severity low|medium|high] [--force]",
	"sudors-check": "sudodrift sudors-check [--root DIR] [--format text|json] [--target ubuntu-26.04|ubuntu-25.10|upstream] [--fail-on breaks|differs|info]",
	"report":       "sudodrift report base.json current.json -o report.html [--ignore FILE] [--min-severity low|medium|high]",
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s\n\nOptions (single or double dash both work):\n", usageLines[name])
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags wraps parseInterspersed, turning flag errors into errUsage after
// the flag package has reported them.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	pos, err := parseInterspersed(fs, args)
	if err != nil && err != flag.ErrHelp {
		return nil, errUsage
	}
	return pos, err
}

func cmdSnapshot(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("snapshot", stderr)
	out := fs.String("o", "", "output file (default: stdout)")
	fs.StringVar(out, "output", "", "output file")
	root := fs.String("root", "/", "filesystem root to scan (use a fake root for tests)")
	home := fs.Bool("include-home", false, "also walk /home for SUID and world-writable files (slower)")
	excl := fs.String("exclude", "", "comma-separated extra directories to skip while walking")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("snapshot takes no positional arguments (got %q)", pos[0])
	}
	var ex []string
	for _, e := range strings.Split(*excl, ",") {
		if e = strings.TrimSpace(e); e != "" {
			ex = append(ex, e)
		}
	}
	s, err := snapshot.Collect(snapshot.Options{Root: *root, IncludeHome: *home, Exclude: ex, ToolVersion: version})
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out == "" || *out == "-" {
		_, err = stdout.Write(b)
		return err
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "snapshot written to %s: %d users, %d groups, %d ssh keys, %d sudoers lines, %d SUID/SGID files, %d world-writable, %d warnings\n",
		*out, len(s.Users), len(s.Groups), len(s.AuthorizedKeys), len(s.Sudoers), len(s.SUIDFiles), len(s.WorldWritable), len(s.Warnings))
	return nil
}

func loadSnapshot(path string) (*snapshot.Snapshot, error) {
	s, _, err := loadSnapshotRaw(path)
	return s, err
}

// loadSnapshotRaw also returns the file bytes, for the evidence bundle.
func loadSnapshotRaw(path string) (*snapshot.Snapshot, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var s snapshot.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, fmt.Errorf("%s: not a valid snapshot: %w", path, err)
	}
	if s.Tool != "sudodrift" || s.Schema != snapshot.SchemaVersion {
		return nil, nil, fmt.Errorf("%s: unsupported snapshot (tool=%q schema=%d)", path, s.Tool, s.Schema)
	}
	return &s, b, nil
}

type compareFlags struct {
	ignore, minSev, out, format, failOn string
}

// filterChanges compares two snapshots and applies the ignore file and the
// minimum severity.
func filterChanges(base, cur *snapshot.Snapshot, cf *compareFlags) (*report.Input, diff.Severity, error) {
	min, err := diff.ParseSeverity(cf.minSev)
	if err != nil {
		return nil, 0, err
	}
	m, err := ignore.Load(cf.ignore)
	if err != nil {
		return nil, 0, fmt.Errorf("ignore file: %w", err)
	}
	kept, ignored := diff.Filter(diff.Compare(base, cur), m, min)
	return &report.Input{Base: base, Current: cur, Changes: kept, Ignored: ignored, ToolVersion: version}, min, nil
}

func compareSetup(name string, args []string, stderr io.Writer, wantOut bool) (*report.Input, *compareFlags, error) {
	wantFormat := name == "diff"
	fs := newFlagSet(name, stderr)
	cf := &compareFlags{}
	fs.StringVar(&cf.ignore, "ignore", "", "ignore file (line-based patterns; .txt or .yaml)")
	fs.StringVar(&cf.minSev, "min-severity", "low", "hide changes below this severity (low|medium|high)")
	if wantFormat {
		fs.StringVar(&cf.format, "format", "text", "output format: text, json or csv")
		fs.StringVar(&cf.failOn, "fail-on", "", "exit 1 only if a shown change is at this severity or above (low|medium|high)")
	}
	if wantOut {
		fs.StringVar(&cf.out, "o", "", "output HTML file (required)")
		fs.StringVar(&cf.out, "output", "", "output HTML file")
	}
	pos, err := parseFlags(fs, args)
	if err != nil {
		return nil, nil, err
	}
	if len(pos) != 2 {
		return nil, nil, fmt.Errorf("%s needs exactly two snapshot files: base.json current.json", name)
	}
	if wantOut && cf.out == "" {
		return nil, nil, fmt.Errorf("report requires -o report.html")
	}
	if wantFormat && !report.ValidFormat(cf.format) {
		return nil, nil, fmt.Errorf("unknown format %q (want %s)", cf.format, strings.Join(report.Formats, ", "))
	}
	if cf.failOn != "" {
		if _, err := diff.ParseSeverity(cf.failOn); err != nil {
			return nil, nil, fmt.Errorf("--fail-on: %w", err)
		}
	}
	base, err := loadSnapshot(pos[0])
	if err != nil {
		return nil, nil, err
	}
	cur, err := loadSnapshot(pos[1])
	if err != nil {
		return nil, nil, err
	}
	in, _, err := filterChanges(base, cur, cf)
	if err != nil {
		return nil, nil, err
	}
	return in, cf, nil
}

func cmdDiff(args []string, stdout, stderr io.Writer) (int, error) {
	in, cf, err := compareSetup("diff", args, stderr, false)
	if err != nil {
		return 2, err
	}
	if err := report.Write(stdout, cf.format, *in); err != nil {
		return 2, err
	}
	// Without --fail-on any shown change is drift. With it, only changes at
	// that level or above set exit code 1; the output is the same either way.
	fail := diff.Low
	if cf.failOn != "" {
		fail, _ = diff.ParseSeverity(cf.failOn) // checked in compareSetup
	}
	for _, c := range in.Changes {
		if c.Severity >= fail {
			return 1, nil
		}
	}
	return 0, nil
}

func cmdReport(args []string, stdout, stderr io.Writer) error {
	in, cf, err := compareSetup("report", args, stderr, true)
	if err != nil {
		return err
	}
	f, err := os.Create(cf.out)
	if err != nil {
		return err
	}
	if err := report.WriteHTML(f, *in); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s := diff.Summarize(in.Changes)
	fmt.Fprintf(stderr, "report written to %s (%d changes: %d high, %d medium, %d low)\n", cf.out, s.Total, s.High, s.Medium, s.Low)
	return nil
}

func cmdEvidence(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("evidence", stderr)
	cf := &compareFlags{}
	basePath := fs.String("base", "", "base snapshot (required)")
	curPath := fs.String("current", "", "current snapshot (required)")
	dir := fs.String("dir", "", "write the bundle into this new or empty directory instead of a zip")
	force := fs.Bool("force", false, "replace an existing zip file")
	fs.StringVar(&cf.out, "o", "", "output zip file (default: evidence-HOST-DATE.zip in the current directory)")
	fs.StringVar(&cf.out, "output", "", "output zip file")
	fs.StringVar(&cf.ignore, "ignore", "", "ignore file (line-based patterns; .txt or .yaml)")
	fs.StringVar(&cf.minSev, "min-severity", "low", "hide changes below this severity (low|medium|high)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("evidence takes no positional arguments (got %q); use --base and --current", pos[0])
	}
	if *basePath == "" || *curPath == "" {
		return fmt.Errorf("evidence needs --base base.json and --current now.json")
	}
	if *dir != "" && cf.out != "" {
		return fmt.Errorf("use either -o or --dir, not both")
	}
	base, baseRaw, err := loadSnapshotRaw(*basePath)
	if err != nil {
		return err
	}
	cur, curRaw, err := loadSnapshotRaw(*curPath)
	if err != nil {
		return err
	}
	in, min, err := filterChanges(base, cur, cf)
	if err != nil {
		return err
	}
	now := time.Now()
	files, err := evidence.Build(evidence.Input{
		Report: *in, BaseRaw: baseRaw, CurrentRaw: curRaw,
		BaseName: filepath.Base(*basePath), CurName: filepath.Base(*curPath),
		MinSev: min, Now: now,
		IgnoreFile: ignoreName(cf.ignore),
	})
	if err != nil {
		return err
	}
	dest := *dir
	if dest != "" {
		err = evidence.WriteDir(dest, files)
	} else {
		dest = cf.out
		if dest == "" {
			dest = evidence.DefaultName(cur.Hostname, now)
		}
		err = evidence.WriteZip(dest, files, now, *force)
	}
	if err != nil {
		return err
	}
	s := diff.Summarize(in.Changes)
	fmt.Fprintf(stderr, "evidence bundle written to %s (%d files, %d changes: %d high, %d medium, %d low)\n", dest, len(files), s.Total, s.High, s.Medium, s.Low)
	fmt.Fprintln(stderr, "note: this collects material for a human review. It is not a signature and not a compliance result.")
	return nil
}

func ignoreName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func cmdSudorsCheck(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("sudors-check", stderr)
	root := fs.String("root", "/", "filesystem root that holds etc/sudoers (use a copy or a fake root for tests)")
	format := fs.String("format", "text", "output format: text or json")
	target := fs.String("target", sudors.DefaultTarget, "sudo-rs release to check against: ubuntu-26.04 (0.2.13), ubuntu-25.10 (0.2.8) or upstream (0.2.15)")
	failOn := fs.String("fail-on", "breaks", "exit 1 if a finding is at this severity or above (breaks|differs|info)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return 2, err
	}
	if len(pos) > 0 {
		return 2, fmt.Errorf("sudors-check takes no positional arguments (got %q); use --root", pos[0])
	}
	t, err := sudors.FindTarget(*target)
	if err != nil {
		return 2, err
	}
	fail, err := sudors.ParseSeverity(*failOn)
	if err != nil {
		return 2, fmt.Errorf("--fail-on: %w", err)
	}
	if *format != "text" && *format != "json" {
		return 2, fmt.Errorf("unknown format %q (want text or json)", *format)
	}
	res, err := sudors.Check(*root, t)
	if err != nil {
		return 2, err
	}
	if err := sudors.Write(stdout, *format, res); err != nil {
		return 2, err
	}
	if res.Worst() >= fail {
		return 1, nil
	}
	return 0, nil
}
