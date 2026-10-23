// Package fixture builds fake root directories for tests and demos.
package fixture

import (
	"os"
	"path/filepath"
	"testing"
)

// Real ed25519-format public key blobs (synthetic; no private key exists) and
// their SHA256 fingerprints as ssh-keygen would print them.
const (
	AliceBlob = "AAAAC3NzaC1lZDI1NTE5AAAAICvYBsl/DgCvGh/DMo+nY6kmlyPI24+sT5OvcdsYbW6Q"
	AliceFP   = "SHA256:F9PpGsngzsZUNdILKaPPnVMowTBXWl43kYojRg2Y8lg"
	BobBlob   = "AAAAC3NzaC1lZDI1NTE5AAAAIIG2N9j80sbaY1nmljEToRcN55XktyW4TR4LTP2exYzp"
	BobFP     = "SHA256:mdjRRFt76vijB/211jtzs1JjGFJR6LVIbEqfsGAoPR4"
	MalBlob   = "AAAAC3NzaC1lZDI1NTE5AAAAIMCkl3YbF1N57WM5fMmAVGVZ+qhMqcvu3ncxF8MVCLas"
	MalFP     = "SHA256:BjSpGY4Pvc0NGK+0HiRFIbuKs0DLXwdrhb9FMiTAu5M"
)

// FileMode converts a classic unix mode (e.g. 0o4755) to Go's os.FileMode,
// which uses different bit positions for setuid/setgid/sticky.
func FileMode(m uint32) os.FileMode {
	fm := os.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		fm |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		fm |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// Write creates (or overwrites) a file under root, making parent dirs, and
// sets its mode explicitly (immune to umask).
func Write(t testing.TB, root, rel, content string, mode uint32) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, FileMode(mode)); err != nil {
		t.Fatal(err)
	}
}

// Chmod is a fatal-on-error chmod relative to root.
func Chmod(t testing.TB, root, rel string, mode uint32) {
	t.Helper()
	if err := os.Chmod(filepath.Join(root, rel), FileMode(mode)); err != nil {
		t.Fatal(err)
	}
}

// Base builds a small, plausible "known good" host.
func Base(t testing.TB, root string) {
	t.Helper()
	Write(t, root, "etc/hostname", "demo-host\n", 0o644)
	Write(t, root, "etc/passwd", ""+
		"root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"+
		"bob:x:1001:1001:Bob:/home/bob:/bin/bash\n", 0o644)
	Write(t, root, "etc/shadow", ""+
		"root:!:19000:0:99999:7:::\n"+
		"daemon:*:19000:0:99999:7:::\n"+
		"alice:$6$salt$hashhashhash:19000:0:99999:7:::\n"+
		"bob:$6$salt$otherhash:19000:0:99999:7:::\n", 0o640)
	Write(t, root, "etc/group", ""+
		"root:x:0:\n"+
		"sudo:x:27:alice\n"+
		"docker:x:999:\n"+
		"alice:x:1000:\n"+
		"bob:x:1001:\n", 0o644)
	Write(t, root, "etc/sudoers", ""+
		"# sudoers\n"+
		"Defaults env_reset\n"+
		"root ALL=(ALL:ALL) ALL\n"+
		"%sudo ALL=(ALL:ALL) ALL\n"+
		"@includedir /etc/sudoers.d\n", 0o440)
	Write(t, root, "etc/sudoers.d/README", "# nothing here\n", 0o440)
	Write(t, root, "etc/ssh/sshd_config", ""+
		"# sshd\n"+
		"PermitRootLogin no\n"+
		"PasswordAuthentication no\n"+
		"PubkeyAuthentication yes\n", 0o600)
	Write(t, root, "home/alice/.ssh/authorized_keys",
		"ssh-ed25519 "+AliceBlob+" alice@laptop\n", 0o600)
	Chmod(t, root, "home/alice/.ssh", 0o700)
	Write(t, root, "usr/bin/sudo", "#!/bin/sh\necho sudo\n", 0o755)
	Chmod(t, root, "usr/bin/sudo", 0o4755)
	Write(t, root, "usr/bin/foo", "#!/bin/sh\necho foo\n", 0o755)
	Write(t, root, "usr/bin/wall", "#!/bin/sh\necho wall\n", 0o755)
	Chmod(t, root, "usr/bin/wall", 0o2755)
}

// Drift applies a set of suspicious modifications to a Base() root.
func Drift(t testing.TB, root string) {
	t.Helper()
	// new UID 0 backdoor account + new regular user
	Write(t, root, "etc/passwd", ""+
		"root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"+
		"bob:x:1001:1001:Bob:/home/bob:/bin/bash\n"+
		"toor:x:0:0:backdoor:/root:/bin/bash\n"+
		"mallory:x:1002:1002::/home/mallory:/bin/bash\n", 0o644)
	Write(t, root, "etc/group", ""+
		"root:x:0:\n"+
		"sudo:x:27:alice,bob\n"+
		"docker:x:999:mallory\n"+
		"alice:x:1000:\n"+
		"bob:x:1001:\n"+
		"mallory:x:1002:\n", 0o644)
	// sudo rules
	Write(t, root, "etc/sudoers.d/90-ops", "bob ALL=(ALL) NOPASSWD: ALL\n", 0o440)
	// ssh keys
	Write(t, root, "home/bob/.ssh/authorized_keys",
		"ssh-ed25519 "+BobBlob+" bob@workstation\n", 0o600)
	Chmod(t, root, "home/bob/.ssh", 0o700)
	Write(t, root, "home/alice/.ssh/authorized_keys",
		"ssh-ed25519 "+AliceBlob+" alice@laptop\n"+
			"from=\"10.0.0.0/8\" ssh-ed25519 "+MalBlob+" totally-legit\n", 0o600)
	// SUID + world-writable + shadow loosened + sshd weakened
	Chmod(t, root, "usr/bin/foo", 0o4755)
	Write(t, root, "etc/cron.hourly/cleanup.sh", "#!/bin/sh\n", 0o666)
	Chmod(t, root, "etc/shadow", 0o644)
	Write(t, root, "etc/ssh/sshd_config", ""+
		"PermitRootLogin yes\n"+
		"PasswordAuthentication yes\n"+
		"PubkeyAuthentication yes\n", 0o600)
}
