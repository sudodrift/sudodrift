// Package ignore implements sudodrift's tiny line-based ignore file.
//
// Each non-blank, non-comment line is a wildcard pattern ('*' any run of
// characters including '/' and ':', '?' one character) matched against either
// "<category>:<subject>" or just "<subject>" of a change. Examples:
//
//	suid:/usr/bin/sudo
//	ssh_key:deploy:*
//	/usr/lib/*
//	user:build*
//
// YAML-ish lists are tolerated: a leading "- " is stripped, quotes are
// removed, and bare "key:" header lines (e.g. "ignore:") are skipped.
package ignore

import (
	"bufio"
	"io"
	"os"
	"strings"
)

type Matcher struct{ patterns []string }

func Load(path string) (*Matcher, error) {
	if path == "" {
		return &Matcher{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (*Matcher, error) {
	m := &Matcher{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		l = strings.TrimSpace(strings.TrimPrefix(l, "- "))
		l = strings.Trim(l, `"'`)
		if l == "" || (strings.HasSuffix(l, ":") && !strings.ContainsAny(l, "*?/")) {
			continue
		}
		m.patterns = append(m.patterns, l)
	}
	return m, sc.Err()
}

func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.patterns)
}

// Match reports whether the change identified by category+subject is ignored.
func (m *Matcher) Match(category, subject string) bool {
	if m == nil {
		return false
	}
	full := category + ":" + subject
	for _, p := range m.patterns {
		if wildcard(p, full) || wildcard(p, subject) {
			return true
		}
	}
	return false
}

func wildcard(pat, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pat) && (pat[p] == '?' || pat[p] == s[i]) && pat[p] != '*':
			p++
			i++
		case p < len(pat) && pat[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}
