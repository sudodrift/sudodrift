package sudors

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sudodrift/sudodrift/internal/snapshot"
)

// includeLimit matches the hard limit sudo-rs and original sudo use.
const includeLimit = 128

type checker struct {
	root    string
	target  Target
	seen    map[string]bool
	order   map[string]int
	files   []string
	out     []Finding
	depth   int
	aliases map[string]aliasDef
}

type aliasDef struct {
	file string
	line int
}

// Check reads the sudoers tree under root (use "/" for the live system) and
// returns every finding for target.
func Check(root string, target Target) (*Result, error) {
	if root == "" {
		root = "/"
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	c := &checker{root: root, target: target, seen: map[string]bool{}, order: map[string]int{}, aliases: map[string]aliasDef{}}

	main := "/etc/sudoers"
	if _, err := os.Stat(c.host("/etc/sudoers-rs")); err == nil {
		c.add(Finding{
			Severity:    Info,
			Rule:        "sudoers-rs-file",
			File:        "/etc/sudoers-rs",
			Explanation: "sudo-rs reads /etc/sudoers-rs instead of /etc/sudoers when that file exists, so /etc/sudoers is not used by sudo-rs on this system.",
			Fix:         "Make sure /etc/sudoers-rs holds the rules you expect. This check reads /etc/sudoers-rs.",
			Source:      srcSudoersR,
		})
		main = "/etc/sudoers-rs"
	}
	if err := c.file(main, true); err != nil {
		return nil, err
	}
	c.unreferenced()

	c.out = dropShadowed(c.out)
	sortFindings(c.out, c.order)
	r := &Result{Target: target.Name, SudoRS: target.Version.String(), Files: c.files, Findings: c.out}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	if r.Files == nil {
		r.Files = []string{}
	}
	return r, nil
}

func (c *checker) host(p string) string { return filepath.Join(c.root, filepath.FromSlash(p)) }

func (c *checker) add(f Finding) { c.out = append(c.out, f) }

// file checks one sudoers file. A missing top-level file is an error; a
// missing included file is a finding, as in sudo-rs.
func (c *checker) file(logical string, top bool) error {
	if c.seen[logical] {
		return nil
	}
	b, err := os.ReadFile(c.host(logical))
	if err != nil {
		if top {
			return fmt.Errorf("cannot read %s: %w", logical, err)
		}
		return err
	}
	c.seen[logical] = true
	c.order[logical] = len(c.files)
	c.files = append(c.files, logical)

	if !utf8.Valid(b) {
		c.add(Finding{
			Severity:    Breaks,
			Rule:        "not-utf8",
			File:        logical,
			Line:        firstInvalidLine(b),
			Explanation: "The file is not valid UTF-8. sudo-rs requires the sudoers file to be valid UTF-8.",
			Fix:         "Convert the file to UTF-8, for example with iconv, and check it with visudo -c.",
			Source:      srcReadme,
		})
	}

	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, strings.TrimSuffix(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", logical, err)
	}
	for _, nl := range snapshot.JoinContinuationsNumbered(lines) {
		c.line(logical, nl)
	}
	return nil
}

func firstInvalidLine(b []byte) int {
	for i, l := range bytes.Split(b, []byte("\n")) {
		if !utf8.Valid(l) {
			return i + 1
		}
	}
	return 0
}

// line checks one logical line.
func (c *checker) line(file string, nl snapshot.NumberedLine) {
	n := nl.Line
	text := stripComment(nl.Text)
	var sl snapshot.SudoLine
	if t := strings.TrimSpace(text); len(t) > 1 && t[0] == '#' && t[1] >= '0' && t[1] <= '9' {
		// "#1000 ALL = ..." is a rule for user ID 1000, not a comment.
		sl = snapshot.SudoLine{Kind: "rule", Line: strings.Join(strings.Fields(t), " ")}
	} else {
		var ok bool
		if sl, ok = snapshot.ParseSudoLine(text); !ok {
			return
		}
	}
	// Parse the raw text so the join offsets stay valid; show the
	// whitespace-normalized text in findings.
	lead := len(text) - len(strings.TrimLeft(text, " \t"))
	joins := make([]int, 0, len(nl.Joins))
	for _, j := range nl.Joins {
		joins = append(joins, j-lead)
	}
	l := lineCtx{c: c, file: file, n: n, text: strings.TrimSpace(sl.Line), raw: strings.TrimSpace(text), joins: joins}
	switch sl.Kind {
	case "include":
		c.include(l)
	case "defaults":
		l.defaults()
	case "alias":
		l.alias()
	default:
		l.rule()
	}
}

// stripComment removes a trailing comment. '#' starts a comment unless the
// line is an #include directive or the '#' is followed by a digit (a user or
// group ID such as #1000 or %#100).
func stripComment(s string) string {
	t := strings.TrimLeft(s, " \t")
	if strings.HasPrefix(t, "#include") {
		return s
	}
	inQuote, esc := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case esc:
			esc = false
		case ch == '\\':
			esc = true
		case ch == '"':
			inQuote = !inQuote
		case ch == '#' && !inQuote:
			if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				continue
			}
			return s[:i]
		}
	}
	return s
}

// include follows @include, @includedir, #include and #includedir.
func (c *checker) include(l lineCtx) {
	directive, arg, _ := strings.Cut(l.text, " ")
	arg = strings.TrimSpace(arg)
	isDir := strings.HasSuffix(directive, "includedir")
	p := unquoteIncludePath(arg)
	if p == "" {
		return
	}
	if strings.Contains(p, "%h") {
		if isDir {
			l.add(Breaks, "includedir-percent-h",
				"sudo-rs does not expand %h (the short host name) in @includedir, so it reports an error and reads nothing from that directory.",
				"Replace %h with the literal directory name.", srcInclH)
		} else {
			l.add(Info, "include-percent-h",
				"Original sudo expands %h to the short host name in @include. The sudo-rs manual does not describe %h for @include, so sudo-rs may look for a file with a literal %h in its name.",
				"Use a literal file name, then confirm with sudo-rs visudo -c.", srcManIncl)
		}
		return
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(path.Dir(l.file), p)
	}
	p = path.Clean(p)

	if c.depth >= includeLimit {
		l.add(Breaks, "include-limit", "More than 128 nested include files. sudo-rs stops including here.", "Remove the include loop.", srcManIncl)
		return
	}
	c.depth++
	defer func() { c.depth-- }()

	if !isDir {
		if err := c.file(p, false); err != nil {
			l.add(Info, "include-missing", fmt.Sprintf("Included file %s cannot be read (%v). Both sudo and sudo-rs report this.", p, shortErr(err)),
				"Create the file or remove the include line.", srcManIncl)
		}
		return
	}
	ents, err := os.ReadDir(c.host(p))
	if err != nil {
		l.add(Info, "include-missing", fmt.Sprintf("Included directory %s cannot be read (%v). Both sudo and sudo-rs report this.", p, shortErr(err)),
			"Create the directory or remove the include line.", srcManIncl)
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, "~") || strings.Contains(n, ".") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fp := path.Join(p, n)
		if err := c.file(fp, false); err != nil {
			l.add(Info, "include-missing", fmt.Sprintf("File %s cannot be read (%v).", fp, shortErr(err)), "Fix the file permissions.", srcManIncl)
		}
	}
}

func shortErr(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// unquoteIncludePath handles "quoted paths" and backslash-escaped spaces.
func unquoteIncludePath(s string) string {
	if len(s) >= 2 && s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : end+1]
		}
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == ' ' || s[i] == '\t' {
			break
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unreferenced reports files in /etc/sudoers.d that no include reached.
func (c *checker) unreferenced() {
	ents, err := os.ReadDir(c.host("/etc/sudoers.d"))
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, "~") || strings.Contains(n, ".") {
			continue
		}
		p := "/etc/sudoers.d/" + n
		if c.seen[p] {
			continue
		}
		c.add(Finding{
			Severity:    Info,
			Rule:        "not-included",
			File:        p,
			Explanation: "No @includedir or @include line reaches this file, so neither sudo nor sudo-rs reads it. It was not checked.",
			Fix:         "Add \"@includedir /etc/sudoers.d\" to the main sudoers file if this file should be used.",
			Source:      srcManIncl,
		})
	}
}

// dropShadowed removes info and differs findings on lines that also have a
// breaks finding: sudo-rs skips those lines, so the softer notes do not apply.
func dropShadowed(fs []Finding) []Finding {
	type key struct {
		file string
		line int
	}
	broken := map[key]bool{}
	for _, f := range fs {
		if f.Severity == Breaks && f.Line > 0 {
			broken[key{f.File, f.Line}] = true
		}
	}
	out := fs[:0]
	for _, f := range fs {
		if f.Severity != Breaks && broken[key{f.File, f.Line}] {
			continue
		}
		out = append(out, f)
	}
	return out
}
