package snapshot

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	reNoPasswd = regexp.MustCompile(`\bNOPASSWD\s*:`)
	reRunAsAll = regexp.MustCompile(`\(\s*ALL\s*(:\s*ALL\s*)?\)|=\s*(?:[A-Z_]+\s*:\s*)*ALL\s*$`)
	reAlias    = regexp.MustCompile(`^(User|Runas|Host|Cmnd)_Alias\b`)
)

func (c *collector) collectSudoers() {
	c.parseSudoersFile("/etc/sudoers")
	ents, err := os.ReadDir(c.host("/etc/sudoers.d"))
	c.warnErr("/etc/sudoers.d", err)
	if err == nil {
		for _, e := range ents {
			n := e.Name()
			// sudo ignores names containing '.' or ending in '~'
			if e.IsDir() || strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
				continue
			}
			c.parseSudoersFile("/etc/sudoers.d/" + n)
		}
	}
	sort.SliceStable(c.snap.Sudoers, func(i, j int) bool {
		a, b := c.snap.Sudoers[i], c.snap.Sudoers[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return false
	})
}

func (c *collector) parseSudoersFile(logical string) {
	lines, err := readLines(c.host(logical))
	if err != nil {
		if !os.IsNotExist(err) {
			c.warn("cannot read %s: %v", logical, err)
		}
		return
	}
	for _, l := range JoinContinuations(lines) {
		if sl, ok := ParseSudoLine(l); ok {
			sl.File = logical
			c.snap.Sudoers = append(c.snap.Sudoers, sl)
		}
	}
}

// JoinContinuations merges lines ending in a backslash.
func JoinContinuations(lines []string) []string {
	var out []string
	for _, l := range JoinContinuationsNumbered(lines) {
		out = append(out, l.Text)
	}
	return out
}

// NumberedLine is a logical sudoers line and the 1-based physical line it
// starts on.
type NumberedLine struct {
	Line  int
	Text  string
	Joins []int // byte offsets in Text of the spaces that replaced "\\\n"
}

// JoinContinuationsNumbered merges lines ending in a backslash and keeps the
// starting line number of each logical line, for messages that point at a
// line in the file.
func JoinContinuationsNumbered(lines []string) []NumberedLine {
	var out []NumberedLine
	var cur string
	var joins []int
	start, open := 0, false
	for i, l := range lines {
		if !open {
			start = i + 1
		}
		if strings.HasSuffix(l, "\\") {
			cur += strings.TrimSuffix(l, "\\")
			joins = append(joins, len(cur))
			cur += " "
			open = true
			continue
		}
		out = append(out, NumberedLine{Line: start, Text: cur + l, Joins: joins})
		cur, joins, open = "", nil, false
	}
	if open {
		out = append(out, NumberedLine{Line: start, Text: cur, Joins: joins})
	}
	return out
}

// ParseSudoLine classifies a single logical sudoers line.
func ParseSudoLine(raw string) (SudoLine, bool) {
	l := strings.Join(strings.Fields(raw), " ")
	if l == "" {
		return SudoLine{}, false
	}
	if strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "#include") {
		return SudoLine{}, false // comment (note: "#1000" uid syntax only appears after a keyword)
	}
	sl := SudoLine{Line: l}
	switch {
	case strings.HasPrefix(l, "#include") || strings.HasPrefix(l, "@include"):
		sl.Kind = "include"
	case strings.HasPrefix(l, "Defaults"):
		sl.Kind = "defaults"
		// "Defaults !authenticate" disables password prompts globally
		if strings.Contains(l, "!authenticate") {
			sl.NoPasswd = true
		}
	case reAlias.MatchString(l):
		sl.Kind = "alias"
	default:
		sl.Kind = "rule"
		sl.Who = strings.Fields(l)[0]
		sl.NoPasswd = reNoPasswd.MatchString(l)
		sl.RunAsAll = reRunAsAll.MatchString(l)
	}
	if sl.Kind != "rule" && reNoPasswd.MatchString(l) {
		sl.NoPasswd = true
	}
	return sl, true
}
