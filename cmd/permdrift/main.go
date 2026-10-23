// permdrift: Linux permission drift detector.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/permdrift/permdrift/internal/diff"
	"github.com/permdrift/permdrift/internal/ignore"
	"github.com/permdrift/permdrift/internal/report"
	"github.com/permdrift/permdrift/internal/snapshot"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = `permdrift ` + "%s" + `: Linux permission drift detector

Usage:
  permdrift snapshot -o snap.json [--root /] [--include-home] [--exclude DIRS]
  permdrift diff   base.json current.json [--ignore FILE] [--min-severity low|medium|high]
  permdrift report base.json current.json -o report.html [--ignore FILE] [--min-severity LEVEL]
  permdrift version

Exit codes: 0 = no drift, 1 = drift found (diff), 2 = error.
`

func init() {
	// `go install ...@vX.Y.Z` has no -ldflags; fall back to the module version.
	if version == "0.1.0-dev" {
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
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "permdrift", version)
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version)
	default:
		fmt.Fprintf(stderr, "permdrift: unknown command %q\n\n", args[0])
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
		fmt.Fprintln(stderr, "permdrift:", err)
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
	"snapshot": "permdrift snapshot [-o snap.json] [--root DIR] [--include-home] [--exclude DIRS]",
	"diff":     "permdrift diff base.json current.json [--ignore FILE] [--min-severity low|medium|high]",
	"report":   "permdrift report base.json current.json -o report.html [--ignore FILE] [--min-severity low|medium|high]",
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
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s snapshot.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: not a valid snapshot: %w", path, err)
	}
	if s.Tool != "permdrift" || s.Schema != snapshot.SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported snapshot (tool=%q schema=%d)", path, s.Tool, s.Schema)
	}
	return &s, nil
}

type compareFlags struct {
	ignore, minSev, out string
}

func compareSetup(name string, args []string, stderr io.Writer, wantOut bool) (*report.Input, *compareFlags, error) {
	fs := newFlagSet(name, stderr)
	cf := &compareFlags{}
	fs.StringVar(&cf.ignore, "ignore", "", "ignore file (line-based patterns; .txt or .yaml)")
	fs.StringVar(&cf.minSev, "min-severity", "low", "hide changes below this severity (low|medium|high)")
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
	min, err := diff.ParseSeverity(cf.minSev)
	if err != nil {
		return nil, nil, err
	}
	base, err := loadSnapshot(pos[0])
	if err != nil {
		return nil, nil, err
	}
	cur, err := loadSnapshot(pos[1])
	if err != nil {
		return nil, nil, err
	}
	m, err := ignore.Load(cf.ignore)
	if err != nil {
		return nil, nil, fmt.Errorf("ignore file: %w", err)
	}
	kept, ignored := diff.Filter(diff.Compare(base, cur), m, min)
	return &report.Input{Base: base, Current: cur, Changes: kept, Ignored: ignored, ToolVersion: version}, cf, nil
}

func cmdDiff(args []string, stdout, stderr io.Writer) (int, error) {
	in, _, err := compareSetup("diff", args, stderr, false)
	if err != nil {
		return 2, err
	}
	report.WriteText(stdout, *in)
	if len(in.Changes) > 0 {
		return 1, nil
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
