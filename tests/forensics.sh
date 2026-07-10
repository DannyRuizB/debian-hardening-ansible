#!/usr/bin/env bash
# =============================================================================
# Blue-team companion to redteam.sh: stage a fresh, time-boxed attack and then
# reconstruct it from the node's own logs — an incident report built from the
# exact files a real analyst opens. Each section names its SOURCE, so this
# doubles as a tour of where a Debian box records intrusion attempts and the
# defensive actions it took.
#
# It is self-contained: it marks a start time, generates ONE legitimate login
# and then an attack, and analyses only events after that mark — so the report
# never mixes in the earlier Ansible provisioning (which connects as root
# before root login is disabled). It intentionally does NOT clean up, so the
# ban and firewall rule are still live for sections 4-5. Recover with:
#   ../ -> node still hardened; run redteam.sh (it unbans+restarts) or node.sh down
#
# Run it on an already-hardened node:
#   ./node.sh up && ./node.sh wait && <harden with site.yml> && ./forensics.sh
#
# Sources (all on the node, read via docker exec):
#   journalctl -u ssh        -> every SSH auth attempt (sshd)
#   /var/log/fail2ban.log    -> Fail2Ban's ban decisions (NOT the journal)
#   fail2ban-client status   -> live jail counters
#   ufw status               -> firewall rules, incl. Fail2Ban's REJECTs
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
NODE="dh-test-node"
PORT=2222
GOOD=".ssh_ci/id_ci"
EVIL=".attacker/evil"
OPTS=(-p "$PORT" -o StrictHostKeyChecking=no
      -o "UserKnownHostsFile=.ssh_ci/known_hosts"
      -o ConnectTimeout=4 -o BatchMode=yes)

[ -f "$EVIL" ] || { mkdir -p .attacker; chmod 700 .attacker
  ssh-keygen -t ed25519 -f "$EVIL" -N "" -C attacker >/dev/null 2>&1; }

echo ">> Staging a fresh attack to analyse..."
# Start from a clean jail so the report reflects only this run.
docker exec "$NODE" bash -c \
  'for ip in $(fail2ban-client get sshd banned 2>/dev/null | grep -oE "[0-9.]+"); do \
     fail2ban-client set sshd unbanip "$ip"; done; systemctl restart fail2ban' \
  >/dev/null 2>&1
sleep 3

# T0: everything analysed below happens after this node-local timestamp.
T0=$(docker exec "$NODE" date '+%Y-%m-%d %H:%M:%S')

# One legitimate admin login, so the report can contrast good vs hostile.
ssh "${OPTS[@]}" -i "$GOOD" opsadmin@127.0.0.1 true >/dev/null 2>&1

# The attack: waves of failed logins (non-existent users + real accounts with
# a wrong key) until Fail2Ban bans the source.
for wave in 1 2 3; do
  for u in root admin test opsadmin oracle git postgres ubuntu; do
    ssh "${OPTS[@]}" -o ConnectTimeout=3 -i "$EVIL" "$u@127.0.0.1" true >/dev/null 2>&1
  done
  for _ in $(seq 1 8); do
    n=$(docker exec "$NODE" fail2ban-client status sshd 2>/dev/null \
        | grep "Currently banned" | grep -oE "[0-9]+")
    [ "${n:-0}" -ge 1 ] && break 2
    sleep 2
  done
done
sleep 1

# Pull the SSH journal once, limited to our window.
ssh_log=$(docker exec "$NODE" journalctl -u ssh --no-pager -o short-iso --since "$T0" 2>/dev/null)

hr() { printf '%s\n' "-------------------------------------------------------------"; }
echo
echo "============================================================="
echo " INCIDENT REPORT — SSH intrusion attempts on the node"
echo " Window analysed: since $T0 (node time)"
echo "============================================================="

hr; echo " 1. Timeline   [source: journalctl -u ssh]"; hr
first=$(echo "$ssh_log" | grep -iE "invalid user|closed by authenticating" | head -1 | awk '{print $1}')
last=$(echo "$ssh_log"  | grep -iE "invalid user|closed by authenticating" | tail -1 | awk '{print $1}')
echo "  First hostile event : ${first:-<none>}"
echo "  Last hostile event  : ${last:-<none>}"

hr; echo " 2. Where did it come from?   [source: journalctl -u ssh]"; hr
echo "  Attacking IPs (by number of hostile events):"
echo "$ssh_log" | grep -iE "invalid user|closed by authenticating|closed by invalid" \
  | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn \
  | awk '{printf "    %4d hostile events  from %s\n", $1, $2}'

hr; echo " 3. Which accounts were targeted?   [source: journalctl -u ssh]"; hr
echo "  Non-existent users the attacker guessed ('Invalid user'):"
echo "$ssh_log" | grep -oiE "invalid user [a-z0-9_-]+" | awk '{print $3}' \
  | sort | uniq -c | sort -rn | awk '{printf "    x%-3d %s\n", $1, $2}'
echo
echo "  Real accounts probed with a bad key ('closed by authenticating user'):"
echo "$ssh_log" | grep -oiE "closed by authenticating user [a-z0-9_-]+" | awk '{print $5}' \
  | sort | uniq -c | sort -rn | awk '{printf "    x%-3d %s\n", $1, $2}'

hr; echo " 4. How the box defended itself   [source: /var/log/fail2ban.log]"; hr
echo "  Ban decisions in this window:"
# Keep only 'Ban' lines whose timestamp is at/after T0, and print them clean
# as 'YYYY-MM-DD HH:MM:SS  Ban <ip>' (the log stamps are '...HH:MM:SS,millis').
bans=$(docker exec "$NODE" grep -E "\] Ban [0-9]" /var/log/fail2ban.log 2>/dev/null \
  | awk -v t0="$T0" '{ ts=$1" "substr($2,1,8); if (ts >= t0) printf "    %s  Ban %s\n", ts, $NF }')
if [ -n "$bans" ]; then echo "$bans"; else
  echo "    (no ban recorded in this window — attack may not have reached maxretry)"
fi
echo
echo "  Live jail state   [source: fail2ban-client status sshd]:"
docker exec "$NODE" fail2ban-client status sshd 2>/dev/null \
  | grep -iE "failed|banned" | sed 's/^/    /'

hr; echo " 5. Firewall rules dropped in by Fail2Ban   [source: ufw status]"; hr
docker exec "$NODE" ufw status 2>/dev/null | grep -iE "REJECT|DENY" | sed 's/^/    /'
docker exec "$NODE" ufw status 2>/dev/null | grep -qiE "REJECT|DENY" \
  || echo "    (no active ban rules — attacker not currently banned)"

hr; echo " 6. Legitimate access, for contrast   [source: journalctl -u ssh]"; hr
echo "  Successful logins in this window (should be the admin only):"
echo "$ssh_log" | grep -oiE "accepted publickey for [a-z0-9_-]+" | awk '{print $4}' \
  | sort | uniq -c | sort -rn | awk '{printf "    x%-3d %s (key accepted)\n", $1, $2}'
echo "$ssh_log" | grep -qiE "accepted publickey" \
  || echo "    (none — not even the admin logged in during this window)"

hr; echo " Reading guide — the files a defender watches:"; hr
cat <<'EOF'
    journalctl -u ssh            every SSH auth attempt (user, source IP, result)
    /var/log/fail2ban.log        Fail2Ban's Found/Ban/Unban decisions + timestamps
    /var/log/auth.log            the SSH events again on non-systemd setups
    fail2ban-client status sshd  current failure count + active bans
    ufw status verbose           firewall policy + Fail2Ban's REJECT rules
    /etc/fail2ban/jail.local     the ban policy that produced all of the above
    /etc/ssh/sshd_config.d/*.conf the hardening drop-in that refused the logins
EOF
echo "  Note: the ban is still LIVE. Run ./redteam.sh (unbans+restarts) or"
echo "        ./node.sh down to reset."
echo "============================================================="
