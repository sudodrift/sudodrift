package sudors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type lineCtx struct {
	c     *checker
	file  string
	n     int
	text  string // whitespace-normalized, for display
	raw   string // as written (continuations joined), for parsing
	joins []int  // offsets in raw where a backslash-newline was
}

func (l lineCtx) add(sev Severity, rule, expl, fix, src string) {
	l.c.add(Finding{Severity: sev, Rule: rule, File: l.file, Line: l.n, Text: l.text, Explanation: expl, Fix: fix, Source: src})
}

func (l lineCtx) ver() version { return l.c.target.Version }

// lineDropped is appended to every "breaks" explanation.
const lineDropped = " sudo-rs reports a syntax error and skips the whole line, so nothing else on it takes effect either."

var (
	reAliasName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	reTag       = regexp.MustCompile(`^([A-Z_]+)\s*:`)
	reOption    = regexp.MustCompile(`^([A-Z_]+)\s*=\s*("[^"]*"|[^\s,:]+)`)
	reDigest    = regexp.MustCompile(`^(?:sha224|sha256|sha384|sha512)\s*:\s*[^\s,]+(?:\s*,\s*(?:sha224|sha256|sha384|sha512)\s*:\s*[^\s,]+)*`)
	reIPv4      = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reParam     = regexp.MustCompile(`^(!*)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|-=|=)?\s*(.*)$`)
)

var knownTags = map[string]bool{
	"PASSWD": true, "NOPASSWD": true, "SETENV": true, "NOSETENV": true, "EXEC": true, "NOEXEC": true,
	"LOG_INPUT": true, "NOLOG_INPUT": true, "LOG_OUTPUT": true, "NOLOG_OUTPUT": true,
	"MAIL": true, "NOMAIL": true, "FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

var knownOptions = map[string]bool{
	"CWD": true, "CHROOT": true, "TIMEOUT": true, "NOTBEFORE": true, "NOTAFTER": true,
	"ROLE": true, "TYPE": true, "APPARMOR_PROFILE": true, "PRIVS": true, "LIMITPRIVS": true,
}

// ---- scanning helpers ----

// splitTop splits s on sep where sep is not escaped, quoted or inside parens.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, inQuote, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '\\':
			i++
		case ch == '"':
			inQuote = !inQuote
		case inQuote:
		case ch == '(':
			depth++
		case ch == ')':
			if depth > 0 {
				depth--
			}
		case ch == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// scanList reads a comma-separated list (users or hosts) from s and returns
// the items and the rest of the string. The list ends at whitespace that is
// not followed by a comma, or at stop.
func scanList(s string, stop byte) ([]string, string) {
	var items []string
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		inQuote := false
		for i < len(s) {
			ch := s[i]
			if ch == '\\' {
				i += 2
				continue
			}
			if ch == '"' {
				inQuote = !inQuote
			} else if !inQuote && (ch == ' ' || ch == '\t' || ch == ',' || ch == stop) {
				break
			}
			i++
		}
		if i > len(s) {
			i = len(s)
		}
		if i > start {
			items = append(items, s[start:i])
		}
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j < len(s) && s[j] == ',' {
			i = j + 1
			continue
		}
		return items, s[i:]
	}
}

func skipWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// cutWord splits s at the first run of spaces or tabs.
func cutWord(s string) (string, string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

func stripBang(s string) string { return strings.TrimLeft(strings.TrimSpace(s), "! \t") }

// ---- users and hosts ----

func (l lineCtx) checkUser(item, where string) {
	u := stripBang(item)
	if strings.Contains(u, "\\ ") && l.ver().less(version{0, 2, 9}) {
		l.add(Breaks, "user-escaped-space",
			fmt.Sprintf("Escaped space in %s (%s). sudo-rs %s does not accept \"\\ \" in user or group names (\"illegal escape sequence\"). sudo-rs 0.2.9 added it.%s", where, u, l.ver(), lineDropped),
			"Use the group ID (%#GID) instead, or check whether your Ubuntu package has the fix.", srcUserSpace)
		return
	}
	switch {
	case strings.HasPrefix(u, "+"):
		l.add(Breaks, "netgroup",
			fmt.Sprintf("Netgroup %s in %s. sudo-rs does not support netgroups.%s", u, where, lineDropped),
			"List the users or a Unix group (%group) instead of the netgroup.", srcNetgroup)
	case strings.HasPrefix(u, "%:"):
		l.add(Differs, "nonunix-group",
			fmt.Sprintf("Non-Unix group %s in %s. sudo-rs accepts the syntax but ignores the entry at run time and prints \"warning: non-unix group was ignored\", so members get no access from it.", u, where),
			"Use a Unix group (%group) that the directory service exposes through NSS.", srcNonunix)
	}
}

func (l lineCtx) checkHost(item string) {
	h := stripBang(item)
	if h == "" || h == "ALL" || reAliasName.MatchString(h) {
		return
	}
	switch {
	case strings.HasPrefix(h, "+"):
		l.add(Breaks, "netgroup",
			fmt.Sprintf("Host netgroup %s. sudo-rs does not support netgroups.%s", h, lineDropped),
			"List the host names, or use ALL.", srcNetgroup)
	case strings.ContainsAny(h, "*?["):
		l.add(Breaks, "host-wildcard",
			fmt.Sprintf("Wildcard in host name %s. The sudo-rs parser only accepts letters, digits, '.', '-' and '_' in host names (\"expected host name\"), even though its manual still describes host wildcards.%s", h, lineDropped),
			"List each host name, or use a Host_Alias, or ALL.", srcIPv4)
	case strings.ContainsAny(h, ":/"):
		l.add(Breaks, "host-address",
			fmt.Sprintf("Network address %s used as a host. sudo-rs only matches host names, not IP addresses or networks.%s", h, lineDropped),
			"Use the host name (as printed by hostname), or ALL.", srcIPv4)
	case reIPv4.MatchString(h):
		if l.ver().less(v0213) {
			l.add(Differs, "host-address",
				fmt.Sprintf("IP address %s used as a host. sudo-rs %s treats it as a host name, so it never matches. sudo-rs 0.2.13 and later reject the line.", h, l.ver()),
				"Use the host name (as printed by hostname), or ALL.", srcIPv4)
		} else {
			l.add(Breaks, "host-address",
				fmt.Sprintf("IP address %s used as a host. sudo-rs only matches host names (\"hosts cannot be specified using an IPv4 address\").%s", h, lineDropped),
				"Use the host name (as printed by hostname), or ALL.", srcIPv4)
		}
	}
}

var reAliasDefStart = regexp.MustCompile(`^\s*[A-Z][A-Z0-9_]*\s*=`)

// splitAliasDefs splits "A = x, y : B = z" into its definitions. A ':' only
// starts a new definition when a NAME = follows, so %:group stays intact.
func splitAliasDefs(body string) []string {
	var out []string
	for _, p := range splitTop(body, ':') {
		if len(out) > 0 && !reAliasDefStart.MatchString(p) {
			out[len(out)-1] += ":" + p
			continue
		}
		out = append(out, p)
	}
	return out
}

// splitRunas splits "users : groups" on the first ':' that is not part of
// a %:group entry.
func splitRunas(spec string) []string {
	for i := 0; i < len(spec); i++ {
		if spec[i] == ':' && (i == 0 || spec[i-1] != '%') {
			return []string{spec[:i], spec[i+1:]}
		}
	}
	return []string{spec}
}

func (l lineCtx) checkRunas(spec string) {
	for _, part := range splitRunas(spec) {
		for _, u := range splitTop(part, ',') {
			if u = strings.TrimSpace(u); u != "" {
				l.checkUser(u, "a Runas list")
			}
		}
	}
}

// ---- commands ----

// splitArgs splits a command on unescaped spaces and unescapes it. bad lists
// escape sequences sudo-rs does not allow in commands.
func splitArgs(s string) (words []string, bad []string) {
	var cur strings.Builder
	have := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			n := s[i+1]
			if !strings.ContainsRune("\\,:=# ", rune(n)) {
				bad = append(bad, s[i:i+2])
			}
			cur.WriteByte(n)
			have = true
			i++
			continue
		}
		if ch == ' ' || ch == '\t' {
			if have {
				words = append(words, cur.String())
				cur.Reset()
				have = false
			}
			continue
		}
		cur.WriteByte(ch)
		have = true
	}
	if have {
		words = append(words, cur.String())
	}
	return words, bad
}

func (l lineCtx) checkCommand(raw string) {
	cmd := stripBang(raw)
	if cmd == "" || cmd == "ALL" || reAliasName.MatchString(cmd) {
		return
	}
	if strings.HasPrefix(cmd, "^") {
		l.add(Breaks, "regex",
			"The command is a regular expression (^...$). Original sudo 1.9.10 and later support this. sudo-rs does not support regular expressions."+lineDropped,
			"List the allowed commands as full paths. A shell-style wildcard in the path (for example /usr/bin/foo*) is allowed.", srcRegex)
		return
	}
	words, bad := splitArgs(cmd)
	if len(words) == 0 {
		return
	}
	if len(bad) > 0 {
		l.add(Breaks, "illegal-escape",
			fmt.Sprintf("The command uses the escape %s. In commands sudo-rs only accepts escaped '\\', ',', ':', '=', '#' and space (\"illegal escape sequence\").%s", strings.Join(bad, " "), lineDropped),
			"Remove the backslash. If it was there to stop wildcard matching, note that sudo-rs already compares arguments literally.", srcArgs)
		return
	}
	path, args := words[0], words[1:]
	if path == "sudoedit" {
		if len(args) > 0 {
			l.add(Info, "sudoedit-files",
				"This rule lets a user edit specific files with sudoedit. USN-8708-1 (1 September 2026) fixed a race in sudo-rs sudoedit that let such a user place files in any directory and possibly gain root. It only affects systems with fine-grained sudoedit rules like this one. On Ubuntu 26.04 the fix is in sudo-rs 0.2.13-0ubuntu1.2.",
				"Run apt update && apt upgrade, and check with: dpkg-query -W sudo-rs", srcUSN)
		}
		return
	}
	if len(args) == 0 {
		return
	}
	if strings.HasPrefix(args[0], "^") {
		if l.ver().less(version{0, 2, 11}) {
			l.add(Differs, "regex",
				fmt.Sprintf("The arguments are a regular expression (^...$). sudo-rs %s compares them as plain text, so the rule never matches. Later releases reject the line.", l.ver()),
				"List the exact arguments, or end the rule with a single * to allow any arguments.", srcRegex)
		} else {
			l.add(Breaks, "regex",
				"The arguments are a regular expression (^...$). Original sudo 1.9.10 and later support this. sudo-rs does not support regular expressions."+lineDropped,
				"List the exact arguments, or end the rule with a single * to allow any arguments.", srcRegex)
		}
		return
	}
	trailingStar := false
	switch args[len(args)-1] {
	case "*":
		trailingStar = true
		args = args[:len(args)-1]
	case `""`:
		args = args[:len(args)-1]
	}
	if l.ver().less(v0213) && trailingStar {
		l.add(Differs, "arg-wildcard",
			fmt.Sprintf("A final * argument means \"any further arguments\" in original sudo. sudo-rs %s compares arguments literally, so it only matches a literal *. sudo-rs 0.2.13 and later support the final *. visudo from the Ubuntu 25.10 package (0.2.8-1ubuntu5.3) still accepts the line, so the literal comparison applies there.", l.ver()),
			"List the allowed argument sets one by one, or allow the command with no argument list at all if that is acceptable.", srcArgs)
	}
	var wild, class []string
	for _, a := range args {
		if strings.ContainsAny(a, "*?") {
			wild = append(wild, a)
		} else if strings.Contains(a, "[") {
			class = append(class, a)
		}
	}
	if len(wild) > 0 {
		if l.ver().less(v0213) {
			l.add(Differs, "arg-wildcard",
				fmt.Sprintf("Wildcard in argument %s. sudo-rs %s compares arguments literally, so this only matches the literal text. sudo-rs 0.2.13 and later reject the line.", strings.Join(wild, " "), l.ver()),
				"List the exact arguments allowed, or put a single * as the last argument to allow any arguments.", srcReadme)
		} else {
			l.add(Breaks, "arg-wildcard",
				fmt.Sprintf("Wildcard in argument %s. sudo-rs only allows a wildcard in arguments as a final, standalone * (\"wildcards are not allowed in command arguments\").%s", strings.Join(wild, " "), lineDropped),
				"List the exact arguments allowed, or put a single * as the last argument to allow any arguments. Wildcards in the command path itself are still fine.", srcArgs)
		}
	}
	if len(class) > 0 {
		l.add(Differs, "arg-charclass",
			fmt.Sprintf("Argument %s contains '['. Original sudo treats [...] as a character class. sudo-rs compares arguments as plain text, so it only matches the literal brackets.", strings.Join(class, " ")),
			"List each allowed argument value as its own command entry.", srcArgMatch)
	}
}

func (l lineCtx) checkTag(tag string) {
	switch tag {
	case "INTERCEPT":
		l.add(Breaks, "tag-unsupported",
			"The INTERCEPT tag is not supported by sudo-rs."+lineDropped,
			"Remove INTERCEPT. NOEXEC is supported on Linux if the goal is to stop shell escapes.", srcTags)
	case "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOW":
		l.add(Differs, "tag-ignored",
			fmt.Sprintf("The %s tag is ignored by sudo-rs. The rule still applies, but sudo-rs has no I/O logging or mail, and visudo -c from sudo-rs reports the tag (\"this tag is ignored by sudo-rs\").", tag),
			fmt.Sprintf("Remove %s:. Use auditd or session recording outside sudo if you need I/O logs.", tag), srcTagWarn)
	}
}

func (l lineCtx) checkOption(name string) {
	switch name {
	case "CHROOT", "TIMEOUT", "NOTBEFORE", "NOTAFTER":
		l.add(Breaks, "option-unsupported",
			fmt.Sprintf("The %s= option is not supported by sudo-rs.%s", name, lineDropped),
			fmt.Sprintf("Remove %s=.", name), srcTags)
	case "ROLE", "TYPE":
		l.add(Breaks, "option-unsupported",
			fmt.Sprintf("The %s= option (SELinux) is not supported by sudo-rs.%s", name, lineDropped),
			fmt.Sprintf("Remove %s=.", name), srcTags)
	case "PRIVS", "LIMITPRIVS":
		l.add(Breaks, "option-unsupported",
			fmt.Sprintf("The %s= option (Solaris privileges) is not supported by sudo-rs.%s", name, lineDropped),
			fmt.Sprintf("Remove %s=.", name), srcTags)
	}
}

// specs walks "host = cmndspec, cmndspec : host = cmndspec ...".
func (l lineCtx) specs(s string) {
	base := len(l.raw) - len(s) // offset of s inside l.raw
	i := 0
	for {
		hosts, rest := scanList(s[i:], '=')
		i = len(s) - len(rest)
		i = skipWS(s, i)
		if i >= len(s) || s[i] != '=' {
			return // not a user specification we understand; sudo reports these too
		}
		for _, h := range hosts {
			l.checkHost(h)
		}
		i++
		newGroup := false
		for !newGroup {
			i = skipWS(s, i)
			if i < len(s) && s[i] == '(' {
				end := strings.IndexByte(s[i:], ')')
				if end < 0 {
					return
				}
				l.checkRunas(s[i+1 : i+end])
				i += end + 1
			}
			for {
				i = skipWS(s, i)
				if m := reTag.FindStringSubmatch(s[i:]); m != nil && knownTags[m[1]] {
					l.checkTag(m[1])
					i += len(m[0])
					continue
				}
				if m := reOption.FindStringSubmatch(s[i:]); m != nil && knownOptions[m[1]] {
					l.checkOption(m[1])
					i += len(m[0])
					continue
				}
				break
			}
			i = skipWS(s, i)
			if m := reDigest.FindString(s[i:]); m != "" {
				l.add(Breaks, "digest",
					"The command has a digest (sha224/sha256/sha384/sha512). sudo-rs does not support digest specifications."+lineDropped,
					"Remove the digest and protect the binary with file permissions instead.", srcDigest)
				i += len(m)
			}
			start, inQuote := i, false
		scan:
			for i < len(s) {
				switch s[i] {
				case '\\':
					i++
				case '"':
					inQuote = !inQuote
				case ',', ':':
					if !inQuote {
						break scan
					}
				}
				i++
			}
			if i > len(s) {
				i = len(s)
			}
			l.checkCommand(s[start:i])
			l.checkLayout(s, start, i, base)
			if i >= len(s) {
				return
			}
			newGroup = s[i] == ':'
			i++
		}
	}
}

// checkLayout reports whitespace inside one command that older sudo-rs
// releases reject with "garbage at end of line":
//   - a backslash-newline between the command and its arguments (fixed in
//     0.2.14, sudo-rs issue #1571)
//   - a tab between the command and its arguments (fixed in 0.2.15)
//
// A continuation or tab before a comma or between list items is fine. Both
// were found by running visudo -c from sudo-rs 0.2.8, 0.2.13 and 0.2.15.
func (l lineCtx) checkLayout(s string, start, end, base int) {
	cmd := strings.TrimSpace(s[start:end])
	if l.ver().less(v0214) {
		for _, j := range l.joins {
			j -= base
			if j <= start || j >= end {
				continue
			}
			if strings.TrimSpace(s[start:j]) == "" || strings.TrimSpace(s[j:end]) == "" {
				continue
			}
			l.add(Breaks, "continuation-in-command",
				fmt.Sprintf("A backslash line continuation splits this command and its arguments across lines. sudo-rs %s does not join lines inside a command and reports \"garbage at end of line\". sudo-rs 0.2.14 fixed this.%s", l.ver(), lineDropped),
				"Put the command and all its arguments on one line. A continuation right after a comma is fine.", srcContinue)
			return
		}
	}
	if l.ver().less(v0215) && strings.Contains(strings.Trim(cmd, " \t"), "\t") {
		l.add(Breaks, "tab-in-command",
			fmt.Sprintf("A tab separates this command from its arguments. sudo-rs %s only accepts spaces there and reports \"garbage at end of line\". sudo-rs 0.2.15 accepts tabs.%s", l.ver(), lineDropped),
			"Replace the tab between the command and its arguments with a space.", srcTab)
	}
}

func (l lineCtx) rule() {
	users, rest := scanList(l.raw, 0)
	for _, u := range users {
		l.checkUser(u, "the user list")
	}
	l.specs(rest)
}

func (l lineCtx) alias() {
	kind, body := cutWord(l.raw)
	for _, def := range splitAliasDefs(body) {
		_, members, ok := strings.Cut(def, "=")
		if !ok {
			continue
		}
		for _, m := range splitTop(members, ',') {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			switch kind {
			case "User_Alias":
				l.checkUser(m, "a User_Alias")
			case "Runas_Alias":
				l.checkUser(m, "a Runas_Alias")
			case "Host_Alias":
				l.checkHost(m)
			case "Cmnd_Alias", "Cmd_Alias":
				l.checkCommand(m)
				if off := strings.Index(l.raw, m); off >= 0 {
					l.checkLayout(l.raw, off, off+len(m), 0)
				}
			}
		}
	}
}

// ---- Defaults ----

func (l lineCtx) defaults() {
	rest := strings.TrimPrefix(l.raw, "Defaults")
	if rest != "" && strings.ContainsRune("@:!>", rune(rest[0])) {
		scope := rest[0]
		items, after := scanList(rest[1:], 0)
		for _, it := range items {
			switch scope {
			case '@':
				l.checkHost(it)
			case ':', '>':
				l.checkUser(it, "a Defaults scope")
			case '!':
				if c := stripBang(it); strings.HasPrefix(c, "^") || reDigest.MatchString(c) {
					l.checkCommand(c)
				}
			}
		}
		rest = after
	}
	for _, p := range splitTop(rest, ',') {
		if p = strings.TrimSpace(p); p != "" {
			l.param(p)
		}
	}
}

func (l lineCtx) param(p string) {
	m := reParam.FindStringSubmatch(p)
	if m == nil {
		return
	}
	bangs, name, op, val := m[1], m[2], m[3], strings.Trim(strings.TrimSpace(m[4]), `"`)
	negated := len(bangs) > 0
	v := l.ver()
	s, ok := lookupSetting(name, v)
	if !ok {
		expl := fmt.Sprintf("sudo-rs %s does not know the Defaults option %q (\"unknown setting\").", v, name)
		fix := fmt.Sprintf("Remove %s from this line, or move it to its own Defaults line so the other options still apply.", name)
		src := srcDefaults
		if since, known := firstRelease(name); known {
			expl = fmt.Sprintf("The Defaults option %q was added in sudo-rs %s. The target (%s, sudo-rs %s) does not know it (\"unknown setting\").", name, since, l.c.target.Name, v)
		} else if note, ok := unknownNotes[name]; ok {
			expl += " " + note
			if strings.Contains(note, "README") {
				src = srcReadme
			} else if strings.Contains(note, "FAQ") {
				src = srcFAQ
			} else if strings.Contains(note, "Ubuntu") {
				src = srcUbuntu
			}
		}
		l.add(Breaks, "defaults-unknown", expl+lineDropped, fix, src)
		return
	}
	bad := func(expl, fix string) { l.add(Breaks, "defaults-invalid", expl+lineDropped, fix, srcDefParse) }
	switch {
	case negated && !s.negatable:
		bad(fmt.Sprintf("%q cannot be negated in sudo-rs (\"cannot be used in a boolean context\").", name), fmt.Sprintf("Set %s to a value instead of using !%s.", name, name))
		return
	case op == "+=" || op == "-=":
		if s.kind != kindList {
			bad(fmt.Sprintf("%q is not a list in sudo-rs, so += and -= are not allowed.", name), fmt.Sprintf("Use %s=VALUE.", name))
			return
		}
	case op == "=":
		if s.kind == kindFlag {
			bad(fmt.Sprintf("%q is a flag in sudo-rs %s and cannot be assigned a value (\"can't assign to boolean setting\").", name, v), fmt.Sprintf("Write \"Defaults %s\" or \"Defaults !%s\".", name, name))
			return
		}
		if msg := badValue(s, val); msg != "" {
			bad(fmt.Sprintf("%q is not a valid value for %s in sudo-rs %s: %s.", val, name, v, msg), fmt.Sprintf("Use one of the values sudo-rs accepts for %s.", name))
			return
		}
	case op == "" && !negated && s.kind != kindFlag:
		bad(fmt.Sprintf("%q needs a value in sudo-rs (\"is not a boolean setting\").", name), fmt.Sprintf("Write %s=VALUE.", name))
		return
	}
	if s.ignored {
		l.ignoredSetting(name, negated, op, val)
	}
}

func badValue(s setting, val string) string {
	switch s.kind {
	case kindEnum:
		for _, ok := range s.values {
			if val == ok {
				return ""
			}
		}
		return "allowed values are " + strings.Join(s.values, ", ")
	case kindInt:
		if s.max > 0 {
			n, err := strconv.Atoi(val)
			if err != nil || n < s.min || n > s.max {
				return fmt.Sprintf("must be a whole number from %d to %d", s.min, s.max)
			}
		}
	}
	return ""
}

// ignoredSetting reports options that sudo-rs parses but ignores. Only
// values that would change behavior in original sudo are "differs".
func (l lineCtx) ignoredSetting(name string, negated bool, op, val string) {
	on := !negated
	// The README lists some ignored options; the rest are marked #ignored
	// in src/defaults/mod.rs.
	src := srcDefaults
	switch name {
	case "env_reset", "visiblepw", "verifypw", "mail_badpass", "always_set_home", "always_query_group_plugin", "match_group_by_gid", "log_denied":
		src = srcReadme
	}
	differs := func(expl, fix string) {
		l.add(Differs, "defaults-ignored", expl, fix, src)
	}
	info := func(expl string) {
		l.add(Info, "defaults-ignored", expl, "No change needed. You can remove the option.", src)
	}
	switch name {
	case "env_reset":
		if negated {
			differs("sudo-rs always resets the environment. !env_reset is ignored, so commands do not get the caller's environment as they would with original sudo.",
				"Add the variables you need to env_keep, for example: Defaults env_keep += \"HTTP_PROXY HTTPS_PROXY\"")
		} else {
			info("env_reset is always on in sudo-rs, so this line has no effect.")
		}
	case "visiblepw":
		if on {
			differs("visiblepw is always off in sudo-rs. The option is ignored, so sudo-rs will not read a password when the terminal would echo it.", "Remove visiblepw.")
		}
	case "insults":
		if on {
			differs("sudo-rs accepts insults but ignores it, so no insults are printed.", "Remove insults.")
		}
	case "lecture":
		if on && val != "never" {
			differs("sudo-rs accepts lecture but ignores it, so no lecture is shown.", "Remove lecture. If users need the message, show it another way, for example in /etc/motd.")
		}
	case "fqdn":
		if on {
			differs("sudo-rs accepts fqdn but ignores it, so rules that depend on fully qualified host names may not match.", "Use the host name exactly as the hostname command prints it, or ALL.")
		}
	case "ignore_dot":
		if negated {
			differs("sudo-rs accepts ignore_dot but ignores it, so !ignore_dot has no effect.", "Remove !ignore_dot and run commands by full path.")
		}
	case "verifypw":
		if negated || (op == "=" && val != "all") {
			differs("sudo-rs ignores verifypw and always behaves like verifypw=all, the default.", "Remove verifypw.")
		}
	case "env_delete":
		differs("sudo-rs ignores env_delete. It starts from a minimal environment and only keeps variables listed in env_keep or env_check.", "Remove env_delete. Make sure env_keep does not include the variables you wanted deleted.")
	case "log_denied":
		if negated {
			differs("sudo-rs always logs denied commands. !log_denied is ignored.", "Remove !log_denied.")
		}
	case "mail_badpass", "mailerpath":
		if on {
			info(fmt.Sprintf("sudo-rs never sends mail, so %s has no effect. It is accepted for compatibility.", name))
		}
	case "always_set_home", "always_query_group_plugin", "match_group_by_gid":
		if on {
			info(fmt.Sprintf("%s does not apply to sudo-rs and is ignored. It is accepted for compatibility.", name))
		}
	}
}
