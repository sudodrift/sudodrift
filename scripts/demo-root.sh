#!/usr/bin/env bash
# Build a small fake filesystem root for demos and docs. Needs no root privileges.
# Usage: scripts/demo-root.sh /tmp/demo-root
set -euo pipefail
ROOT=${1:?usage: demo-root.sh DIR}
rm -rf "$ROOT"
mkdir -p "$ROOT"/etc/{ssh,sudoers.d} "$ROOT"/usr/bin "$ROOT"/home/{alice,bob}/.ssh
echo demo-host > "$ROOT/etc/hostname"
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001:Bob:/home/bob:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n' > "$ROOT/etc/shadow"
printf 'root:x:0:\nsudo:x:27:alice\nalice:x:1000:\nbob:x:1001:\n' > "$ROOT/etc/group"
printf 'Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > "$ROOT/etc/sudoers"
printf 'PermitRootLogin no\nPasswordAuthentication no\n' > "$ROOT/etc/ssh/sshd_config"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICvYBsl/DgCvGh/DMo+nY6kmlyPI24+sT5OvcdsYbW6Q alice@laptop" > "$ROOT/home/alice/.ssh/authorized_keys"
: > "$ROOT/home/bob/.ssh/authorized_keys"
for f in sudo editor; do printf '#!/bin/sh\n' > "$ROOT/usr/bin/$f"; chmod 755 "$ROOT/usr/bin/$f"; done
chmod 4755 "$ROOT/usr/bin/sudo"
chmod 640 "$ROOT/etc/shadow"
chmod 600 "$ROOT"/etc/ssh/sshd_config "$ROOT"/home/*/.ssh/authorized_keys
chmod 700 "$ROOT"/home/*/.ssh
echo "fake root ready: $ROOT"
