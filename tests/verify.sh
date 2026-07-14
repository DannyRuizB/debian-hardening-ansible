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


echo "== Kernel hardening (sysctl) =="
# Ask the kernel for the EFFECTIVE values — not the file we wrote. sysctl
# lives in /usr/sbin, outside the non-root SSH PATH, hence the sudo.
expect_line "ICMP redirects are not accepted" "^0$" sudo sysctl -n net.ipv4.conf.all.accept_redirects
expect_line "ICMP redirects are not sent" "^0$" sudo sysctl -n net.ipv4.conf.all.send_redirects
expect_line "source-routed packets are refused" "^0$" sudo sysctl -n net.ipv4.conf.all.accept_source_route
expect_line "reverse-path filtering is on" "^1$" sudo sysctl -n net.ipv4.conf.all.rp_filter
expect_line "martian packets are logged" "^1$" sudo sysctl -n net.ipv4.conf.all.log_martians
expect_line "SYN cookies are enabled" "^1$" sudo sysctl -n net.ipv4.tcp_syncookies
expect_line "dmesg is restricted to root" "^1$" sudo sysctl -n kernel.dmesg_restrict
expect_line "setuid binaries cannot dump core" "^0$" sudo sysctl -n fs.suid_dumpable
expect_ok "the sysctl drop-in survives reboots" test -s /etc/sysctl.d/99-hardening.conf

echo "== Account policies =="
expect_line "password max age is 365 days" "^PASS_MAX_DAYS[[:space:]]+365$" grep -E "^PASS_MAX_DAYS" /etc/login.defs
expect_line "password min age is 1 day" "^PASS_MIN_DAYS[[:space:]]+1$" grep -E "^PASS_MIN_DAYS" /etc/login.defs
expect_line "password expiry warning is 7 days" "^PASS_WARN_AGE[[:space:]]+7$" grep -E "^PASS_WARN_AGE" /etc/login.defs
expect_line "new accounts get a 30-day inactivity lock" "^INACTIVE=30$" grep "^INACTIVE=" /etc/default/useradd
# Functional, not just the config files: an account created NOW must inherit
# all four values in its shadow entry (min:max:warn:inactive).
on_node sudo useradd probe-aging 2>/dev/null || true
expect_line "a freshly created account inherits 1/365/7/30" "^1:365:7:30$" \
  sudo bash -c "'getent shadow probe-aging | cut -d: -f4-7'"
on_node sudo userdel probe-aging 2>/dev/null || true
# The lockout guard: key-only accounts (locked password) are never aged —
# the admin user this suite logs in with must keep an untouched hash.
expect_line "the key-only admin account is not aged (locked hash untouched)" "^[!*]" \
  sudo bash -c "'getent shadow opsadmin | cut -d: -f2'"

# LAST on purpose: banning the client cuts our own SSH access to the node.
echo "== Fail2Ban really bans =="
# Attack with a mix of NON-existent usernames (root/admin/oracle/...), the way a
# real bot does. These log as 'Invalid user' from the sshd-session process on
# OpenSSH >= 9.8 — which the stock '_COMM=sshd' journal match misses, so this
# exercises the jail's journalmatch fix. Fire waves until the ban lands (fail2ban
# can miss the first attempts right after a restart).
banned=no
for wave in 1 2 3; do
  for u in root admin test oracle git postgres ubuntu daniel; do
    ssh "${OPTS[@]}" -o ConnectTimeout=3 -i "$KEY" "$u@127.0.0.1" true >/dev/null 2>&1 || true
  done
  for _ in $(seq 1 8); do
    if docker exec dh-test-node fail2ban-client status sshd 2>/dev/null \
        | grep -E -q "Currently banned:[[:space:]]+[1-9]"; then
      banned=yes
      break
    fi
    sleep 2
  done
  [ "$banned" = yes ] && break
done
if [ "$banned" = yes ]; then
  pass "repeated failed logins get the attacker banned"
else
  fail "repeated failed logins get the attacker banned"
fi
# fail2ban marks the ban a moment before banaction=ufw inserts the REJECT rule,
# so wait for the rule to land before testing the locked-out login — otherwise
# a fast runner slips a connection through the gap.
for _ in $(seq 1 10); do
  docker exec dh-test-node ufw status 2>/dev/null | grep -qiE "REJECT|DENY" && break
  sleep 1
done
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
