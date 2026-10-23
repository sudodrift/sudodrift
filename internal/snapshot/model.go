// Package snapshot collects a point-in-time picture of the security-relevant
// permission state of a Linux host (or a fake root directory used in tests).
package snapshot

// SchemaVersion is bumped whenever the JSON layout changes incompatibly.
const SchemaVersion = 1

// Snapshot is the full collected state. Everything except the metadata fields
// (Hostname, Timestamp, Root, Warnings, ContentHash) feeds ContentHash.
type Snapshot struct {
	Schema      int    `json:"schema"`
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	Hostname    string `json:"hostname"`
	Timestamp   string `json:"timestamp"`
	Root        string `json:"root"`
	ContentHash string `json:"content_hash"`

	Users          []User            `json:"users"`
	Groups         []Group           `json:"groups"`
	AuthorizedKeys []AuthKey         `json:"authorized_keys"`
	Sudoers        []SudoLine        `json:"sudoers"`
	SUIDFiles      []FileEntry       `json:"suid_sgid_files"`
	WorldWritable  []FileEntry       `json:"world_writable"`
	Sensitive      []FileEntry       `json:"sensitive_files"`
	SSHDConfig     map[string]string `json:"sshd_config"`

	Warnings []string `json:"warnings,omitempty"`
}

// User is one /etc/passwd entry. No password hash is ever stored.
type User struct {
	Name          string `json:"name"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	Gecos         string `json:"gecos,omitempty"`
	Home          string `json:"home"`
	Shell         string `json:"shell"`
	LoginShell    bool   `json:"login_shell"`
	PasswordState string `json:"password_state"` // locked | set | empty | unknown
}

// Group is one /etc/group entry.
type Group struct {
	Name       string   `json:"name"`
	GID        int      `json:"gid"`
	Members    []string `json:"members"`
	Privileged bool     `json:"privileged"` // sudo, wheel, admin, docker, lxd
}

// AuthKey is one authorized_keys entry. Only the fingerprint is stored.
type AuthKey struct {
	User        string `json:"user"`
	File        string `json:"file"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
}

// SudoLine is one logical (continuation-joined) sudoers line.
type SudoLine struct {
	File     string `json:"file"`
	Kind     string `json:"kind"` // rule | defaults | alias | include
	Who      string `json:"who,omitempty"`
	Line     string `json:"line"`
	NoPasswd bool   `json:"nopasswd"`
	RunAsAll bool   `json:"run_as_all"` // ALL=(ALL) style grant
}

// FileEntry describes a file or directory and its permissions.
type FileEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"` // file | dir
	Mode   string `json:"mode"` // octal incl. setuid/setgid/sticky, e.g. "4755"
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"` // content hash, SUID/SGID files only
}

// PrivilegedGroups are group names highlighted by sudodrift.
var PrivilegedGroups = map[string]bool{
	"sudo": true, "wheel": true, "admin": true, "docker": true, "lxd": true,
}
