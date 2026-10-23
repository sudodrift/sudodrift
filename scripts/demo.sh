#!/usr/bin/env bash
# End-to-end demo: build a fake root, snapshot, tamper with it, snapshot again,
# then run diff and report. Needs no root privileges and touches nothing real.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${BIN:-bin/sudodrift}
OUT=${OUT:-examples}
ROOT=$(mktemp -d /tmp/sudodrift-demo.XXXXXX)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$OUT"
if [ ! -x "$BIN" ]; then
  echo "== building $BIN"
  CGO_ENABLED=0 go build -trimpath -o "$BIN" ./cmd/sudodrift
fi

ALICE=AAAAC3NzaC1lZDI1NTE5AAAAICvYBsl/DgCvGh/DMo+nY6kmlyPI24+sT5OvcdsYbW6Q
BOB=AAAAC3NzaC1lZDI1NTE5AAAAIIG2N9j80sbaY1nmljEToRcN55XktyW4TR4LTP2exYzp
MAL=AAAAC3NzaC1lZDI1NTE5AAAAIMCkl3YbF1N57WM5fMmAVGVZ+qhMqcvu3ncxF8MVCLas

mkdir -p "$ROOT"/etc/{ssh,sudoers.d,cron.hourly} "$ROOT"/usr/bin "$ROOT"/home/{alice,bob}/.ssh
echo demo-host > "$ROOT/etc/hostname"
cat > "$ROOT/etc/passwd" <<P
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
P
cat > "$ROOT/etc/shadow" <<P
root:!:19000:0:99999:7:::
alice:\$6\$salt\$x:19000:0:99999:7:::
bob:\$6\$salt\$y:19000:0:99999:7:::
P
cat > "$ROOT/etc/group" <<P
root:x:0:
sudo:x:27:alice
docker:x:999:
alice:x:1000:
bob:x:1001:
P
printf 'Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > "$ROOT/etc/sudoers"
printf 'PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n' > "$ROOT/etc/ssh/sshd_config"
echo "ssh-ed25519 $ALICE alice@laptop" > "$ROOT/home/alice/.ssh/authorized_keys"
for f in sudo wall foo; do printf '#!/bin/sh\n' > "$ROOT/usr/bin/$f"; chmod 755 "$ROOT/usr/bin/$f"; done
chmod 4755 "$ROOT/usr/bin/sudo"; chmod 2755 "$ROOT/usr/bin/wall"
chmod 640 "$ROOT/etc/shadow" "$ROOT/etc/sshd_config" 2>/dev/null || true
chmod 600 "$ROOT/etc/ssh/sshd_config" "$ROOT"/home/*/.ssh/authorized_keys; chmod 700 "$ROOT"/home/*/.ssh

echo "== 1. baseline snapshot"
"$BIN" snapshot --root "$ROOT" -o "$OUT/base.json"

echo "== 2. tamper with the fake host"
cat >> "$ROOT/etc/passwd" <<P
toor:x:0:0:backdoor:/root:/bin/bash
mallory:x:1002:1002::/home/mallory:/bin/bash
P
sed -i 's/^sudo:x:27:alice$/sudo:x:27:alice,bob/; s/^docker:x:999:$/docker:x:999:mallory/' "$ROOT/etc/group"
echo 'bob ALL=(ALL) NOPASSWD: ALL' > "$ROOT/etc/sudoers.d/90-ops"; chmod 440 "$ROOT/etc/sudoers.d/90-ops"
echo "ssh-ed25519 $BOB bob@workstation" > "$ROOT/home/bob/.ssh/authorized_keys"; chmod 600 "$ROOT/home/bob/.ssh/authorized_keys"
echo "from=\"10.0.0.0/8\" ssh-ed25519 $MAL totally-legit" >> "$ROOT/home/alice/.ssh/authorized_keys"
chmod 6755 "$ROOT/usr/bin/wall"   # SGID -> SUID+SGID
chmod 4755 "$ROOT/usr/bin/foo"    # plain -> SUID
printf '#!/bin/sh\n' > "$ROOT/etc/cron.hourly/cleanup.sh"; chmod 666 "$ROOT/etc/cron.hourly/cleanup.sh"
chmod 644 "$ROOT/etc/shadow"
printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\n' > "$ROOT/etc/ssh/sshd_config"

echo "== 3. current snapshot"
"$BIN" snapshot --root "$ROOT" -o "$OUT/current.json"

echo "== 4. diff (exit code 1 = drift)"
set +e
"$BIN" diff "$OUT/base.json" "$OUT/current.json" | tee "$OUT/sample-diff.txt"
echo "diff exit code: ${PIPESTATUS[0]}"
set -e

echo "== 5. HTML report"
"$BIN" report "$OUT/base.json" "$OUT/current.json" -o "$OUT/sample-report.html"

echo "== 6. machine readable diff (json, csv)"
set +e
"$BIN" diff "$OUT/base.json" "$OUT/current.json" --format json > "$OUT/sample-diff.json"
"$BIN" diff "$OUT/base.json" "$OUT/current.json" --format csv > "$OUT/sample-diff.csv"
set -e
python3 -m json.tool "$OUT/sample-diff.json" > /dev/null 2>&1 || [ -z "$(command -v python3)" ] || { echo "sample-diff.json is not valid JSON" >&2; exit 1; }

echo "== 7. evidence bundle (checked, then removed; it is not committed)"
BUNDLE="$ROOT-evidence"
"$BIN" evidence --base "$OUT/base.json" --current "$OUT/current.json" --dir "$BUNDLE"
(cd "$BUNDLE" && sha256sum -c MANIFEST.sha256)
rm -rf "$BUNDLE"
