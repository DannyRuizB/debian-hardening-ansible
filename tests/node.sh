#!/usr/bin/env bash
# =============================================================================
# Test node for the e2e workflow: one privileged systemd container that plays
# the role of a fresh Debian server, reachable at 127.0.0.1:2222.
#
#   ./node.sh up     -> generate the CI SSH key, build the image, boot the node
#   ./node.sh wait   -> block until the node's sshd answers (max 60 s)
#   ./node.sh down   -> remove the node
#
# Everything is local and disposable; "down" leaves nothing running.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="dh-test-node"
NAME="dh-test-node"
PORT=2222
KEY=".ssh_ci/id_ci"

case "${1:-}" in
  up)
    if [ ! -f "$KEY" ]; then
      mkdir -p .ssh_ci
      chmod 700 .ssh_ci
      ssh-keygen -t ed25519 -f "$KEY" -N "" -C "dh-ci" >/dev/null
      echo "CI key created at tests/$KEY"
    fi

    docker build --build-arg PUBKEY="$(cat "$KEY.pub")" -t "$IMAGE" .

    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # Privileged + host cgroups: systemd inside the container needs to manage
    # its own services (sshd, ufw, fail2ban, unattended-upgrades).
    docker run -d --name "$NAME" --hostname debian-node \
      --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
      -p "127.0.0.1:$PORT:22" "$IMAGE" >/dev/null

    # The node is recreated on every run and gets a new host key.
    rm -f .ssh_ci/known_hosts
    echo "Node up (ssh on 127.0.0.1:$PORT)"
    ;;

  wait)
    for i in $(seq 1 30); do
      if ssh -i "$KEY" -p "$PORT" \
          -o StrictHostKeyChecking=accept-new \
          -o UserKnownHostsFile=.ssh_ci/known_hosts \
          -o ConnectTimeout=2 root@127.0.0.1 true 2>/dev/null; then
        echo "Node SSH ready"
        exit 0
      fi
      sleep 2
    done
    echo "ERROR: node SSH not answering after 60 s" >&2
    exit 1
    ;;

  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "Node removed"
    ;;

  *)
    echo "Usage: $0 {up|wait|down}" >&2
    exit 1
    ;;
esac
