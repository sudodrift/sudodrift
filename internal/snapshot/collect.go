package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Options controls what Collect does.
type Options struct {
	Root        string   // filesystem root to scan; "" or "/" means the real root
	IncludeHome bool     // also walk /home (SUID + world-writable); slow on big hosts
	Exclude     []string // extra logical directories to skip during the walk
	ToolVersion string
	Now         func() time.Time
}

// KeyDirs are scanned for world-writable files.
var KeyDirs = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

var defaultSkip = []string{
	"/proc", "/sys", "/dev", "/run", "/snap",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet",
}

const maxWarnings = 25

type collector struct {
	root     string
	opts     Options
	snap     *Snapshot
	uidNames map[int]string
	gidNames map[int]string
	warnN    int
}

func (c *collector) warn(format string, a ...any) {
	c.warnN++
	if len(c.snap.Warnings) < maxWarnings {
		msg := fmt.Sprintf(format, a...)
		if c.root != "/" {
			// report logical paths, not the location of the fake root on this host
			msg = strings.ReplaceAll(msg, strings.TrimSuffix(c.root, "/")+"/", "/")
		}
		c.snap.Warnings = append(c.snap.Warnings, msg)
	}
}

// warnErr records a read/stat failure unless the path simply does not exist.
func (c *collector) warnErr(what string, err error) {
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		c.warn("cannot read %s: %v", what, err)
	}
}

// host maps a logical path (as seen inside the scanned root) to a real path.
// For a fake root, symlinks are resolved chroot-style: absolute targets are
// re-rooted inside the fake root, so a link such as etc/passwd -> /etc/passwd
// can never make permdrift read the live host's files.
func (c *collector) host(logical string) string {
	if c.root == "/" {
		return filepath.Join(c.root, logical)
	}
	return resolveInRoot(c.root, logical)
}

const maxSymlinkHops = 40

func resolveInRoot(root, logical string) string {
	pending := strings.Split(filepath.ToSlash(filepath.Clean("/"+logical)), "/")
	var done []string // resolved components, relative to root
	hops := 0
	for len(pending) > 0 {
		comp := pending[0]
		pending = pending[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(done) > 0 {
				done = done[:len(done)-1]
			}
			continue
		}
		cand := filepath.Join(root, filepath.Join(done...), comp)
		fi, err := os.Lstat(cand)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			done = append(done, comp)
			continue
		}
		hops++
		target, err := os.Readlink(cand)
		if hops > maxSymlinkHops || err != nil {
			return filepath.Join(root, ".permdrift-unresolvable-symlink")
		}
		if strings.HasPrefix(target, "/") {
			done = nil
		}
		pending = append(strings.Split(filepath.ToSlash(target), "/"), pending...)
	}
	return filepath.Join(root, filepath.Join(done...))
}

// Collect gathers a snapshot. Unreadable items are recorded as warnings rather
// than aborting, so an unprivileged run still yields a useful (partial) result.
func Collect(opts Options) (*Snapshot, error) {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("root %q is not a directory", root)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	s := &Snapshot{
		Schema:      SchemaVersion,
		Tool:        "permdrift",
		ToolVersion: opts.ToolVersion,
		Timestamp:   now().UTC().Format(time.RFC3339),
		Root:        root,
		SSHDConfig:  map[string]string{},
		// non-nil so empty sections serialise as [] rather than null
		Users: []User{}, Groups: []Group{}, AuthorizedKeys: []AuthKey{}, Sudoers: []SudoLine{},
		SUIDFiles: []FileEntry{}, WorldWritable: []FileEntry{}, Sensitive: []FileEntry{},
	}
	s.Hostname = hostname(root)
	c := &collector{root: root, opts: opts, snap: s, uidNames: map[int]string{}, gidNames: map[int]string{}}

	c.collectPasswdGroup()
	c.collectAuthorizedKeys()
	c.collectSudoers()
	c.collectSSHD()
	c.walk()
	c.collectSensitive()

	sort.Slice(s.SUIDFiles, func(i, j int) bool { return s.SUIDFiles[i].Path < s.SUIDFiles[j].Path })
	sort.Slice(s.WorldWritable, func(i, j int) bool { return s.WorldWritable[i].Path < s.WorldWritable[j].Path })
	if c.warnN > len(s.Warnings) {
		s.Warnings = append(s.Warnings, fmt.Sprintf("... and %d more warnings", c.warnN-len(s.Warnings)))
	}
	s.ContentHash = ComputeHash(s)
	return s, nil
}

func hostname(root string) string {
	if root != "/" {
		if b, err := os.ReadFile(filepath.Join(root, "etc/hostname")); err == nil {
			if h := strings.TrimSpace(string(b)); h != "" {
				return h
			}
		}
	}
	h, _ := os.Hostname()
	return h
}

// ComputeHash hashes the collected data, excluding volatile metadata, so two
// snapshots of an unchanged system have identical hashes.
func ComputeHash(s *Snapshot) string {
	cp := *s
	cp.Hostname, cp.Timestamp, cp.Root, cp.ContentHash, cp.Warnings = "", "", "", "", nil
	cp.ToolVersion = ""
	b, _ := json.Marshal(&cp)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---- users & groups ----

var nonLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/bin/sync": true, "/sbin/halt": true, "/sbin/shutdown": true, "/nonexistent": true,
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

func classifyPassword(field string) string {
	switch {
	case field == "":
		return "empty"
	case strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*"):
		return "locked"
	default:
		return "set"
	}
}

func (c *collector) collectPasswdGroup() {
	s := c.snap
	shadow := map[string]string{}
	if lines, err := readLines(c.host("/etc/shadow")); err == nil {
		for _, l := range lines {
			f := strings.Split(l, ":")
			if len(f) >= 2 && f[0] != "" {
				shadow[f[0]] = classifyPassword(f[1])
			}
		}
	}
	lines, err := readLines(c.host("/etc/passwd"))
	if err != nil {
		c.warn("cannot read /etc/passwd: %v", err)
	}
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) < 7 {
			c.warn("/etc/passwd line %d malformed", i+1)
			continue
		}
		uid, e1 := strconv.Atoi(f[2])
		gid, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil {
			c.warn("/etc/passwd line %d has non-numeric uid/gid", i+1)
			continue
		}
		shell := f[6]
		u := User{Name: f[0], UID: uid, GID: gid, Gecos: f[4], Home: f[5], Shell: shell}
		u.LoginShell = !nonLoginShells[shell] && shell != ""
		if shell == "" {
			u.LoginShell = true // empty shell means /bin/sh
		}
		switch {
		case f[1] != "x":
			u.PasswordState = classifyPassword(f[1])
		case shadow[f[0]] != "":
			u.PasswordState = shadow[f[0]]
		default:
			u.PasswordState = "unknown"
		}
		s.Users = append(s.Users, u)
		if _, dup := c.uidNames[uid]; !dup {
			c.uidNames[uid] = u.Name
		}
	}
	sort.Slice(s.Users, func(i, j int) bool { return s.Users[i].Name < s.Users[j].Name })

	glines, err := readLines(c.host("/etc/group"))
	if err != nil {
		c.warn("cannot read /etc/group: %v", err)
	}
	for i, l := range glines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) < 4 {
			c.warn("/etc/group line %d malformed", i+1)
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		g := Group{Name: f[0], GID: gid, Members: []string{}, Privileged: PrivilegedGroups[f[0]]}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		sort.Strings(g.Members)
		s.Groups = append(s.Groups, g)
		if _, dup := c.gidNames[gid]; !dup {
			c.gidNames[gid] = g.Name
		}
	}
	sort.Slice(s.Groups, func(i, j int) bool { return s.Groups[i].Name < s.Groups[j].Name })
}

// ---- file helpers ----

func (c *collector) entry(logical string, fi os.FileInfo) FileEntry {
	m := fi.Mode()
	bits := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		bits |= 04000
	}
	if m&os.ModeSetgid != 0 {
		bits |= 02000
	}
	if m&os.ModeSticky != 0 {
		bits |= 01000
	}
	uid, gid := ownerIDs(fi)
	e := FileEntry{Path: logical, Type: "file", Mode: fmt.Sprintf("%04o", bits), UID: uid, GID: gid}
	if fi.IsDir() {
		e.Type = "dir"
	} else {
		e.Size = fi.Size()
	}
	e.Owner = c.name(c.uidNames, uid)
	e.Group = c.name(c.gidNames, gid)
	return e
}

func (c *collector) name(m map[int]string, id int) string {
	if n, ok := m[id]; ok {
		return n
	}
	return strconv.Itoa(id)
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func under(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// ---- filesystem walk: SUID/SGID + world-writable ----

func (c *collector) walk() {
	skip := append([]string{}, defaultSkip...)
	skip = append(skip, c.opts.Exclude...)
	if !c.opts.IncludeHome {
		skip = append(skip, "/home")
	}
	keyDirs := append([]string{}, KeyDirs...)
	if c.opts.IncludeHome {
		keyDirs = append(keyDirs, "/home")
	}
	_ = filepath.WalkDir(c.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			c.warn("walk %s: %v", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(c.root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		logical := "/" + filepath.ToSlash(rel)
		if d.IsDir() {
			for _, sk := range skip {
				if under(logical, filepath.Clean(sk)) {
					return fs.SkipDir
				}
			}
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		m := info.Mode()
		inKey := false
		for _, k := range keyDirs {
			if under(logical, k) {
				inKey = true
				break
			}
		}
		switch {
		case m.IsRegular():
			if m&(os.ModeSetuid|os.ModeSetgid) != 0 {
				e := c.entry(logical, info)
				e.SHA256 = hashFile(p)
				c.snap.SUIDFiles = append(c.snap.SUIDFiles, e)
			}
			if inKey && m.Perm()&0002 != 0 {
				c.snap.WorldWritable = append(c.snap.WorldWritable, c.entry(logical, info))
			}
		case m.IsDir():
			if inKey && m.Perm()&0002 != 0 && m&os.ModeSticky == 0 {
				c.snap.WorldWritable = append(c.snap.WorldWritable, c.entry(logical, info))
			}
		}
		return nil
	})
}

// ---- sensitive files ----

func (c *collector) collectSensitive() {
	seen := map[string]bool{}
	add := func(logical string) bool {
		if seen[logical] {
			return true
		}
		fi, err := os.Stat(c.host(logical))
		if err != nil {
			c.warnErr(logical, err) // missing files are simply absent; unreadable ones are flagged
			return false
		}
		seen[logical] = true
		c.snap.Sensitive = append(c.snap.Sensitive, c.entry(logical, fi))
		return true
	}
	for _, p := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
		"/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config"} {
		add(p)
	}
	listDir := func(dir string, match func(string) bool) {
		ents, err := os.ReadDir(c.host(dir))
		if err != nil {
			if dir != "/etc/sudoers.d" { // already reported by collectSudoers
				c.warnErr(dir, err)
			}
			return
		}
		for _, e := range ents {
			if match == nil || match(e.Name()) {
				add(dir + "/" + e.Name())
			}
		}
	}
	listDir("/etc/sudoers.d", nil)
	listDir("/etc/ssh", func(n string) bool {
		return strings.HasPrefix(n, "ssh_host_") && strings.HasSuffix(n, "_key")
	})
	homes := map[string]bool{}
	for _, u := range c.snap.Users {
		if u.Home == "" || homes[u.Home] {
			continue
		}
		homes[u.Home] = true
		ssh := strings.TrimSuffix(u.Home, "/") + "/.ssh"
		if add(ssh) {
			listDir(ssh, nil)
		}
	}
	sort.Slice(c.snap.Sensitive, func(i, j int) bool { return c.snap.Sensitive[i].Path < c.snap.Sensitive[j].Path })
}

// ---- sshd_config ----

var sshdKeys = map[string]bool{
	"permitrootlogin": true, "passwordauthentication": true,
	"permitemptypasswords": true, "pubkeyauthentication": true,
}

// collectSSHD records a few high-impact directives (first occurrence wins,
// Match blocks ignored), mirroring sshd's own precedence rules.
func (c *collector) collectSSHD() {
	lines, err := readLines(c.host("/etc/ssh/sshd_config"))
	if err != nil {
		return
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(strings.Replace(l, "=", " ", 1))
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if k == "match" {
			break
		}
		if sshdKeys[k] {
			if _, ok := c.snap.SSHDConfig[k]; !ok {
				c.snap.SSHDConfig[k] = strings.ToLower(f[1])
			}
		}
	}
}
