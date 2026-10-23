// Package diff compares two snapshots and produces semantic, severity-ranked
// changes ("user alice added to group sudo") rather than raw JSON deltas.
package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sudodrift/sudodrift/internal/ignore"
	"github.com/sudodrift/sudodrift/internal/snapshot"
)

type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "High"
	case Medium:
		return "Medium"
	default:
		return "Low"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity parses low|medium|high (case-insensitive).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "low", "":
		return Low, nil
	case "medium", "med":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want low, medium or high)", s)
}

// Change types.
const (
	Added   = "added"
	Removed = "removed"
	Changed = "changed"
)

type Change struct {
	Type     string   `json:"type"`
	Category string   `json:"category"`
	Subject  string   `json:"subject"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Summary counts changes by type and severity.
type Summary struct {
	Total, Added, Removed, Changed int
	High, Medium, Low              int
	ByCategory                     map[string]int
}

func Summarize(cs []Change) Summary {
	s := Summary{ByCategory: map[string]int{}}
	for _, c := range cs {
		s.Total++
		switch c.Type {
		case Added:
			s.Added++
		case Removed:
			s.Removed++
		default:
			s.Changed++
		}
		switch c.Severity {
		case High:
			s.High++
		case Medium:
			s.Medium++
		default:
			s.Low++
		}
		s.ByCategory[c.Category]++
	}
	return s
}

// Filter drops ignored changes and those below min. It returns the kept
// changes and the number ignored by pattern.
func Filter(cs []Change, m *ignore.Matcher, min Severity) (kept []Change, ignored int) {
	for _, c := range cs {
		if m.Match(c.Category, c.Subject) {
			ignored++
			continue
		}
		if c.Severity < min {
			continue
		}
		kept = append(kept, c)
	}
	return kept, ignored
}

type differ struct {
	base, cur *snapshot.Snapshot
	out       []Change
	privUsers map[string]bool // users who are uid 0 or in a privileged group (current)
}

func (d *differ) add(typ, cat, subj string, sev Severity, format string, a ...any) {
	d.out = append(d.out, Change{Type: typ, Category: cat, Subject: subj, Severity: sev, Message: fmt.Sprintf(format, a...)})
}

// Compare returns all changes between base and cur, sorted by severity (high
// first), then category and subject.
func Compare(base, cur *snapshot.Snapshot) []Change {
	d := &differ{base: base, cur: cur, privUsers: map[string]bool{}}
	for _, u := range cur.Users {
		if u.UID == 0 {
			d.privUsers[u.Name] = true
		}
	}
	for _, g := range cur.Groups {
		if g.Privileged {
			for _, m := range g.Members {
				d.privUsers[m] = true
			}
		}
	}
	d.users()
	d.groups()
	d.sshKeys()
	d.sudoers()
	d.suid()
	d.worldWritable()
	d.sensitive()
	d.sshd()
	sort.SliceStable(d.out, func(i, j int) bool {
		a, b := d.out[i], d.out[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Subject < b.Subject
	})
	return d.out
}

// ---- users ----

func (d *differ) privGID(gid int) (string, bool) {
	for _, g := range d.cur.Groups {
		if g.GID == gid && g.Privileged {
			return g.Name, true
		}
	}
	return "", false
}

func (d *differ) users() {
	old := map[string]snapshot.User{}
	for _, u := range d.base.Users {
		old[u.Name] = u
	}
	now := map[string]snapshot.User{}
	for _, u := range d.cur.Users {
		now[u.Name] = u
		o, existed := old[u.Name]
		if !existed {
			sev := Medium
			extra := ""
			if u.UID == 0 {
				sev, extra = High, ", UID 0 (root-equivalent)"
			} else if g, ok := d.privGID(u.GID); ok {
				sev, extra = High, ", primary group "+g
			}
			login := "no login shell"
			if u.LoginShell {
				login = "login shell " + u.Shell
			}
			d.add(Added, "user", u.Name, sev, "user %s added (uid=%d, %s)%s", u.Name, u.UID, login, extra)
			continue
		}
		if o.UID != u.UID {
			sev := Medium
			if u.UID == 0 {
				sev = High
			}
			d.add(Changed, "user", u.Name+":uid", sev, "user %s UID changed %d -> %d", u.Name, o.UID, u.UID)
		}
		if o.GID != u.GID {
			sev := Medium
			extra := ""
			if g, ok := d.privGID(u.GID); ok {
				sev, extra = High, " (privileged group "+g+")"
			}
			d.add(Changed, "user", u.Name+":gid", sev, "user %s primary GID changed %d -> %d%s", u.Name, o.GID, u.GID, extra)
		}
		if o.Shell != u.Shell {
			sev := Low
			if !o.LoginShell && u.LoginShell {
				sev = Medium
				if u.UID == 0 {
					sev = High
				}
			}
			d.add(Changed, "user", u.Name+":shell", sev, "user %s shell changed %s -> %s", u.Name, o.Shell, u.Shell)
		}
		if o.Home != u.Home {
			d.add(Changed, "user", u.Name+":home", Medium, "user %s home changed %s -> %s", u.Name, o.Home, u.Home)
		}
		if o.PasswordState != u.PasswordState && o.PasswordState != "unknown" && u.PasswordState != "unknown" {
			sev := Low
			switch {
			case u.PasswordState == "empty":
				sev = High
			case o.PasswordState == "locked" && u.PasswordState == "set":
				sev = Medium
			}
			d.add(Changed, "user", u.Name+":password", sev, "user %s password state changed %s -> %s", u.Name, o.PasswordState, u.PasswordState)
		}
	}
	for _, u := range d.base.Users {
		if _, ok := now[u.Name]; !ok {
			d.add(Removed, "user", u.Name, Low, "user %s removed", u.Name)
		}
	}
}

// ---- groups ----

func (d *differ) groups() {
	old := map[string]snapshot.Group{}
	for _, g := range d.base.Groups {
		old[g.Name] = g
	}
	now := map[string]bool{}
	for _, g := range d.cur.Groups {
		now[g.Name] = true
		o, existed := old[g.Name]
		if !existed {
			sev := Low
			if g.Privileged {
				sev = Medium
			}
			d.add(Added, "group", g.Name, sev, "group %s added (gid=%d)", g.Name, g.GID)
			for _, m := range g.Members {
				d.memberAdded(g, m)
			}
			continue
		}
		if o.GID != g.GID {
			d.add(Changed, "group", g.Name+":gid", Medium, "group %s GID changed %d -> %d", g.Name, o.GID, g.GID)
		}
		om := toSet(o.Members)
		gm := toSet(g.Members)
		for _, m := range g.Members {
			if !om[m] {
				d.memberAdded(g, m)
			}
		}
		for _, m := range o.Members {
			if !gm[m] {
				d.add(Removed, "group_member", g.Name+":"+m, Low, "user %s removed from group %s", m, g.Name)
			}
		}
	}
	for _, g := range d.base.Groups {
		if !now[g.Name] {
			d.add(Removed, "group", g.Name, Low, "group %s removed", g.Name)
		}
	}
}

func (d *differ) memberAdded(g snapshot.Group, member string) {
	sev := Low
	tag := ""
	if g.Privileged {
		sev, tag = High, " (privileged group)"
	}
	d.add(Added, "group_member", g.Name+":"+member, sev, "user %s added to group %s%s", member, g.Name, tag)
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
}

// ---- authorized_keys ----

func (d *differ) sshKeys() {
	key := func(k snapshot.AuthKey) string { return k.User + ":" + k.Fingerprint }
	old := map[string]snapshot.AuthKey{}
	for _, k := range d.base.AuthorizedKeys {
		old[key(k)] = k
	}
	now := map[string]bool{}
	for _, k := range d.cur.AuthorizedKeys {
		now[key(k)] = true
		o, existed := old[key(k)]
		if !existed {
			sev := Medium
			note := ""
			if d.privUsers[k.User] {
				sev, note = High, " [privileged user]"
			}
			c := ""
			if k.Comment != "" {
				c = fmt.Sprintf(", comment %q", k.Comment)
			}
			opt := ""
			if k.Options != "" {
				opt = ", options: " + k.Options
			}
			d.add(Added, "ssh_key", key(k), sev, "SSH key %s added for user %s (%s%s%s)%s", k.Fingerprint, k.User, k.Type, c, opt, note)
			continue
		}
		if o.Options != k.Options {
			sev := Low
			if len(k.Options) < len(o.Options) {
				sev = Medium // restrictions removed
			}
			d.add(Changed, "ssh_key", key(k)+":options", sev, "SSH key %s for user %s options changed: %q -> %q", k.Fingerprint, k.User, o.Options, k.Options)
		}
	}
	for _, k := range d.base.AuthorizedKeys {
		if !now[key(k)] {
			d.add(Removed, "ssh_key", key(k), Low, "SSH key %s removed for user %s", k.Fingerprint, k.User)
		}
	}
}

// ---- sudoers ----

func sudoKey(l snapshot.SudoLine) string { return l.File + ": " + l.Line }

func (d *differ) sudoers() {
	old := map[string]snapshot.SudoLine{}
	for _, l := range d.base.Sudoers {
		old[sudoKey(l)] = l
	}
	now := map[string]bool{}
	for _, l := range d.cur.Sudoers {
		now[sudoKey(l)] = true
		if _, ok := old[sudoKey(l)]; ok {
			continue
		}
		sev := Medium
		var tags []string
		if l.NoPasswd {
			tags = append(tags, "NOPASSWD")
			sev = High
		}
		if l.RunAsAll {
			tags = append(tags, "ALL=(ALL)")
			sev = High
		}
		switch l.Kind {
		case "rule":
			label := "sudo rule"
			if len(tags) > 0 {
				label = strings.Join(tags, " + ") + " sudo rule"
			}
			d.add(Added, "sudoers", sudoKey(l), sev, "%s added for %s in %s: %s", label, l.Who, l.File, l.Line)
		case "defaults":
			if !l.NoPasswd {
				sev = Medium
			}
			d.add(Added, "sudoers", sudoKey(l), sev, "sudoers Defaults added in %s: %s", l.File, l.Line)
		default:
			if !l.NoPasswd {
				sev = Low
				if l.Kind == "include" {
					sev = Medium
				}
			}
			d.add(Added, "sudoers", sudoKey(l), sev, "sudoers %s added in %s: %s", l.Kind, l.File, l.Line)
		}
	}
	for _, l := range d.base.Sudoers {
		if !now[sudoKey(l)] {
			d.add(Removed, "sudoers", sudoKey(l), Low, "sudoers %s removed from %s: %s", l.Kind, l.File, l.Line)
		}
	}
}

// ---- file helpers ----

func modeBits(m string) uint32 {
	v, _ := strconv.ParseUint(m, 8, 32)
	return uint32(v)
}

func describeSUID(bits uint32) string {
	switch {
	case bits&04000 != 0 && bits&02000 != 0:
		return "SUID+SGID"
	case bits&04000 != 0:
		return "SUID"
	case bits&02000 != 0:
		return "SGID"
	}
	return "plain"
}

// ---- SUID / SGID ----

func (d *differ) suid() {
	old := map[string]snapshot.FileEntry{}
	for _, f := range d.base.SUIDFiles {
		old[f.Path] = f
	}
	now := map[string]bool{}
	for _, f := range d.cur.SUIDFiles {
		now[f.Path] = true
		nb := modeBits(f.Mode)
		o, existed := old[f.Path]
		if !existed {
			kind := describeSUID(nb)
			sev := Medium
			if nb&04000 != 0 && f.UID == 0 {
				sev = High
			}
			d.add(Added, "suid", f.Path, sev, "%s is now %s (owner %s, mode %s; new file or mode change)", f.Path, kind, f.Owner, f.Mode)
			continue
		}
		ob := modeBits(o.Mode)
		if ob != nb {
			switch {
			case nb&04000 != 0 && ob&04000 == 0:
				d.add(Changed, "suid", f.Path, High, "%s became SUID (mode %s -> %s)", f.Path, o.Mode, f.Mode)
			case nb&02000 != 0 && ob&02000 == 0:
				d.add(Changed, "suid", f.Path, Medium, "%s became SGID (mode %s -> %s)", f.Path, o.Mode, f.Mode)
			default:
				d.add(Changed, "suid", f.Path, Low, "%s mode changed %s -> %s", f.Path, o.Mode, f.Mode)
			}
		}
		if o.UID != f.UID || o.GID != f.GID {
			sev := Medium
			if nb&04000 != 0 {
				sev = High
			}
			d.add(Changed, "suid", f.Path+":owner", sev, "%s ownership changed %s:%s -> %s:%s", f.Path, o.Owner, o.Group, f.Owner, f.Group)
		}
		if o.SHA256 != "" && f.SHA256 != "" && o.SHA256 != f.SHA256 {
			sev := Medium
			if nb&04000 != 0 && f.UID == 0 {
				sev = High
			}
			d.add(Changed, "suid", f.Path+":content", sev, "%s content changed (%s file; sha256 %s -> %s)", f.Path, describeSUID(nb), short(o.SHA256), short(f.SHA256))
		}
	}
	for _, f := range d.base.SUIDFiles {
		if !now[f.Path] {
			d.add(Removed, "suid", f.Path, Low, "%s no longer SUID/SGID (removed or mode change)", f.Path)
		}
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ---- world-writable ----

func (d *differ) worldWritable() {
	old := map[string]snapshot.FileEntry{}
	for _, f := range d.base.WorldWritable {
		old[f.Path] = f
	}
	now := map[string]bool{}
	for _, f := range d.cur.WorldWritable {
		now[f.Path] = true
		sev := High
		if strings.HasPrefix(f.Path, "/home/") {
			sev = Medium
		}
		kind := "file"
		if f.Type == "dir" {
			kind = "directory (no sticky bit)"
		}
		o, existed := old[f.Path]
		if !existed {
			d.add(Added, "world_writable", f.Path, sev, "%s is now world-writable %s (mode %s)", f.Path, kind, f.Mode)
		} else if o.Mode != f.Mode {
			d.add(Changed, "world_writable", f.Path, Medium, "world-writable %s mode changed %s -> %s", f.Path, o.Mode, f.Mode)
		}
	}
	for _, f := range d.base.WorldWritable {
		if !now[f.Path] {
			d.add(Removed, "world_writable", f.Path, Low, "%s is no longer world-writable", f.Path)
		}
	}
}

// ---- sensitive file permissions ----

func isSecret(path string) bool {
	base := path[strings.LastIndex(path, "/")+1:]
	switch {
	case path == "/etc/shadow" || path == "/etc/gshadow":
		return true
	case strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub"):
		return true
	case strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key"):
		return true
	}
	return false
}

func isSSHAuth(path string) bool {
	return strings.HasSuffix(path, "/.ssh") || strings.Contains(path, "/.ssh/authorized_keys")
}

// laxState evaluates whether a mode is dangerous on its own.
func laxState(f snapshot.FileEntry) (Severity, string) {
	b := modeBits(f.Mode)
	switch {
	case b&0002 != 0:
		return High, "world-writable"
	case isSecret(f.Path) && b&0044 != 0:
		return High, "readable by group/others"
	case isSSHAuth(f.Path) && b&0020 != 0:
		return High, "group-writable"
	case b&06000 != 0:
		return High, "setuid/setgid"
	}
	return 0, ""
}

func (d *differ) sensitive() {
	old := map[string]snapshot.FileEntry{}
	for _, f := range d.base.Sensitive {
		old[f.Path] = f
	}
	now := map[string]bool{}
	for _, f := range d.cur.Sensitive {
		now[f.Path] = true
		o, existed := old[f.Path]
		if !existed {
			if sev, why := laxState(f); sev > 0 {
				d.add(Added, "file_perm", f.Path, sev, "%s added with unsafe permissions: %s (mode %s, %s:%s)", f.Path, why, f.Mode, f.Owner, f.Group)
			} else {
				d.add(Added, "file_perm", f.Path, Low, "sensitive %s %s added (mode %s, %s:%s)", f.Type, f.Path, f.Mode, f.Owner, f.Group)
			}
			continue
		}
		ob, nb := modeBits(o.Mode), modeBits(f.Mode)
		if ob != nb {
			extra := nb &^ ob
			sev := Low
			verb := "tightened"
			if extra != 0 {
				verb = "loosened"
				sev = Medium
				if why, bad := looseReason(f, extra); bad {
					sev = High
					verb += " (" + why + ")"
				}
			}
			d.add(Changed, "file_perm", f.Path+":mode", sev, "%s permissions %s: %s -> %s", f.Path, verb, o.Mode, f.Mode)
		}
		if o.UID != f.UID || o.GID != f.GID {
			sev := Medium
			if strings.HasPrefix(f.Path, "/etc/") && f.UID != 0 {
				sev = High
			}
			d.add(Changed, "file_perm", f.Path+":owner", sev, "%s ownership changed %s:%s -> %s:%s", f.Path, o.Owner, o.Group, f.Owner, f.Group)
		}
	}
	for _, f := range d.base.Sensitive {
		if now[f.Path] {
			continue
		}
		sev := Low
		switch f.Path {
		case "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/passwd", "/etc/group":
			sev = Medium
		}
		d.add(Removed, "file_perm", f.Path, sev, "sensitive %s %s removed", f.Type, f.Path)
	}
}

func looseReason(f snapshot.FileEntry, extra uint32) (string, bool) {
	switch {
	case extra&0002 != 0:
		return "now world-writable", true
	case extra&06000 != 0:
		return "setuid/setgid added", true
	case isSecret(f.Path) && extra&0044 != 0:
		return "secret now readable by group/others", true
	case isSSHAuth(f.Path) && extra&0020 != 0:
		return "now group-writable", true
	}
	return "", false
}

// ---- sshd_config ----

var sshdRisky = map[string]string{
	"permitrootlogin":        "yes",
	"passwordauthentication": "yes",
	"permitemptypasswords":   "yes",
}

func (d *differ) sshd() {
	keys := map[string]bool{}
	for k := range d.base.SSHDConfig {
		keys[k] = true
	}
	for k := range d.cur.SSHDConfig {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		o, hadOld := d.base.SSHDConfig[k]
		n, hasNew := d.cur.SSHDConfig[k]
		if o == n && hadOld == hasNew {
			continue
		}
		switch {
		case !hasNew:
			d.add(Removed, "sshd", k, Low, "sshd_config %s directive removed (was %q; default applies)", k, o)
		default:
			sev := Medium
			if risky, ok := sshdRisky[k]; ok && n == risky {
				sev = High
			}
			typ := Changed
			from := fmt.Sprintf("%q", o)
			if !hadOld {
				typ, from = Added, "unset"
			}
			d.add(typ, "sshd", k, sev, "sshd_config %s: %s -> %q", k, from, n)
		}
	}
}
