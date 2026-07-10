#!/usr/bin/env bash
# =============================================================================
# Post-hardening assertions against the test node. Every promise the README
# makes is checked here for real — from the outside, over SSH, like an
# attacker (or a locked-out admin) would experience it.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PORT=2222
KEY=".ssh_ci/id_ci"
OPTS=(-p "$PORT"
      -o StrictHostKeyChecking=accept-new
      -o "UserKnownHostsFile=.ssh_ci/known_hosts"
      -o ConnectTimeout=5
      -o BatchMode=yes)

failures=0
pass() { echo "  OK   $1"; }
fail() { echo "  FAIL $1"; failures=$((failures + 1)); }

# Run a command on the node as the admin user.
on_node() { ssh "${OPTS[@]}" -i "$KEY" opsadmin@127.0.0.1 "$@"; }

# The remote command must succeed.
expect_ok() {
  local desc="$1"; shift
  if on_node "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# The remote command's output must contain a line matching the regex.
expect_line() {
  local desc="$1" regex="$2"; shift 2
  if on_node "$@" 2>/dev/null | grep -E -q "$regex"; then pass "$desc"; else fail "$desc"; fi
}

echo "== Won't lock you out =="
expect_ok "admin user logs in with their key" true
expect_ok "admin user has passwordless sudo" sudo -n true

echo "== SSH hardening =="
if ssh "${OPTS[@]}" -i "$KEY" root@127.0.0.1 true >/dev/null 2>&1; then
  fail "root SSH login is rejected (even with a valid key)"
else
  pass "root SSH login is rejected (even with a valid key)"
fi
# Ask sshd itself for its EFFECTIVE config — not the file we wrote.
expect_line "sshd effective config: permitrootlogin no" \
  "^permitrootlogin no$" sudo sshd -T
expect_line "sshd effective config: passwordauthentication no" \
  "^passwordauthentication no$" sudo sshd -T
expect_line "sshd effective config: kbdinteractiveauthentication no" \
  "^kbdinteractiveauthentication no$" sudo sshd -T
# What the server OFFERS to clients: password must not be on the menu.
if ssh -v "${OPTS[@]}" -o PubkeyAuthentication=no opsadmin@127.0.0.1 true 2>&1 \
    | grep "Authentications that can continue" | grep -q password; then
  fail "server does not offer password authentication"
else
  pass "server does not offer password authentication"
fi

echo "== Firewall (UFW) =="
expect_line "ufw is active" "Status: active" sudo ufw status
expect_line "default policy: deny incoming" "deny \(incoming\)" sudo ufw status verbose
expect_line "SSH port allowed through the firewall" "^22/tcp +ALLOW" sudo ufw status

echo "== Fail2Ban =="
expect_line "fail2ban service is running" "^active$" sudo systemctl is-active fail2ban
expect_line "sshd jail is enabled" "Currently banned" sudo fail2ban-client status sshd

echo "== Automatic security updates =="
expect_line "unattended-upgrades service is running" "^active$" \
  sudo systemctl is-active unattended-upgrades
expect_line "periodic upgrades are enabled in apt config" \
  'APT::Periodic::Unattended-Upgrade "1"' cat /etc/apt/apt.conf.d/20auto-upgrades

# LAST on purpose: banning the client cuts our own SSH access to the node.
echo "== Fail2Ban really bans =="
for _ in $(seq 1 8); do
  ssh "${OPTS[@]}" -i "$KEY" root@127.0.0.1 true >/dev/null 2>&1 || true
done
# The authoritative view, straight from the jail (SSH may be cut already).
# The ban is applied asynchronously, so poll for it (up to 30 s).
banned=no
for _ in $(seq 1 15); do
  if docker exec dh-test-node fail2ban-client status sshd 2>/dev/null \
      | grep -E -q "Currently banned:[[:space:]]+[1-9]"; then
    banned=yes
    break
  fi
  sleep 2
done
if [ "$banned" = yes ]; then
  pass "repeated failed logins get the attacker banned"
else
  fail "repeated failed logins get the attacker banned"
fi
# And the attacker's experience: even a GOOD key is refused once banned.
if ssh "${OPTS[@]}" -o ConnectTimeout=3 -i "$KEY" opsadmin@127.0.0.1 true >/dev/null 2>&1; then
  fail "banned client is locked out even with a valid key"
else
  pass "banned client is locked out even with a valid key"
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) FAILED"
  exit 1
fi
echo "All checks passed"
