#!/usr/bin/env bash
# =============================================================================
# Red-team / attack simulation against the hardened test node.
#
# This is the adversarial companion to verify.sh: instead of asserting the
# config, it *attacks* the node from the outside and documents what the server
# does. Run it after the node has been hardened:
#
#   ./node.sh up && ./node.sh wait
#   echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
#   ansible-playbook -i inventory_first_run.ini ../site.yml \
#       -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
#   ./redteam.sh
#
# The "attacker" even KNOWS valid passwords (set below) — the worst case for
# the hardening — and still must fail. Everything is local: the target is a
# throwaway container on 127.0.0.1, attacked from your own machine.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

NODE="dh-test-node"
PORT=2222
GOOD=".ssh_ci/id_ci"        # the legitimate admin's key
EVIL=".attacker/evil"       # an unauthorized "attacker" key
OPTS=(-p "$PORT" -o StrictHostKeyChecking=no
      -o "UserKnownHostsFile=.ssh_ci/known_hosts"
      -o ConnectTimeout=6 -o BatchMode=yes)

blocked=0 leaked=0
BLOCK() { echo "  [BLOCKED] $1"; blocked=$((blocked + 1)); }   # attack repelled
LEAK()  { echo "  [!! LEAK] $1"; leaked=$((leaked + 1)); }     # attack succeeded

# Prepare the attacker's key and plant known passwords on the node, so the
# attacker is in the strongest possible position.
[ -f "$EVIL" ] || { mkdir -p .attacker; chmod 700 .attacker
  ssh-keygen -t ed25519 -f "$EVIL" -N "" -C attacker >/dev/null 2>&1; }
docker exec "$NODE" bash -c "echo 'opsadmin:SuperSecret123' | chpasswd; \
  echo 'root:ToorRoot456' | chpasswd" 2>/dev/null

# ssh_denied <key> <user>  -> true if the server refused the login
ssh_denied() { ! ssh "${OPTS[@]}" -i "$1" "$2@127.0.0.1" true >/dev/null 2>&1; }

echo "=============================================================="
echo " RED-TEAM: attacking the hardened node on 127.0.0.1:$PORT"
echo "=============================================================="

# Start from a clean slate: drop any leftover bans from a previous run so
# the script's verdict never depends on prior state.
docker exec "$NODE" bash -c \
  'for ip in $(fail2ban-client get sshd banned 2>/dev/null | grep -oE "[0-9.]+"); do \
     fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1; done' 2>/dev/null

echo
echo "-- Control: the legitimate admin must get in (clean state) ----"
if ssh "${OPTS[@]}" -i "$GOOD" opsadmin@127.0.0.1 "sudo -n true" >/dev/null 2>&1; then
  echo "  [OK] opsadmin logs in with their key and has sudo"
else
  LEAK "legitimate admin cannot log in on a clean node"
fi

echo
echo "-- Phase 1: SSH key logins (Fail2Ban paused to isolate SSH) ---"
docker exec "$NODE" systemctl stop fail2ban 2>/dev/null
ssh_denied "$GOOD" root      && BLOCK "root with a VALID key (PermitRootLogin no)" \
                             || LEAK  "root logged in with a key"
ssh_denied "$EVIL" opsadmin  && BLOCK "opsadmin with an unauthorized key" \
                             || LEAK  "unauthorized key accepted for opsadmin"
ssh_denied "$EVIL" root      && BLOCK "root with an unauthorized key" \
                             || LEAK  "unauthorized key accepted for root"
ssh_denied "$EVIL" hacker    && BLOCK "login as a non-existent user 'hacker'" \
                             || LEAK  "non-existent user logged in"

echo
echo "-- Phase 2: password attacks (attacker KNOWS the passwords) ---"
# Ask the server (via ssh -v) which auth methods it advertises; password
# must not be among them.
methods=$(ssh -v -p "$PORT" -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=.ssh_ci/known_hosts -o ConnectTimeout=6 \
  -o PubkeyAuthentication=no -o PreferredAuthentications=password \
  -o BatchMode=yes opsadmin@127.0.0.1 true 2>&1 \
  | sed -n 's/.*Authentications that can continue: //p' | head -1)
if echo "$methods" | grep -qi password; then
  LEAK "server offers password authentication"
else
  BLOCK "server refuses password auth (only offers: ${methods:-publickey})"
fi

echo
echo "-- Phase 3: brute force -> Fail2Ban ban -----------------------"
docker exec "$NODE" systemctl restart fail2ban 2>/dev/null; sleep 3
# Fire waves of failed logins until the ban lands (fail2ban can miss the very
# first attempts right after a restart while it catches up with the journal).
banned=0
for wave in 1 2 3; do
  for u in root admin test opsadmin oracle git postgres ubuntu; do
    ssh "${OPTS[@]}" -o ConnectTimeout=3 -i "$EVIL" "$u@127.0.0.1" true >/dev/null 2>&1
  done
  for _ in $(seq 1 8); do
    n=$(docker exec "$NODE" fail2ban-client status sshd 2>/dev/null \
        | grep "Currently banned" | grep -oE "[0-9]+")
    [ "${n:-0}" -ge 1 ] && { banned=1; break; }
    sleep 2
  done
  [ "$banned" = 1 ] && break
done
[ "$banned" = 1 ] && BLOCK "brute force got the attacker IP banned" \
                  || LEAK  "brute force did NOT trigger a ban"

echo
echo "-- Phase 4: once banned, even a VALID key is refused ----------"
if ssh "${OPTS[@]}" -i "$GOOD" opsadmin@127.0.0.1 true >/dev/null 2>&1; then
  LEAK "banned IP could still connect"
else
  BLOCK "banned IP rejected at the firewall even with a valid key"
fi

echo
echo "-- Recovery: lift the ban and confirm access is restored -----"
# A plain unbanip isn't enough here: the ban still has ~1h left on its clock
# and the recent failures sit inside the 10-min findtime window, so Fail2Ban
# re-bans on the next tick. The realistic fix an admin would apply is to unban
# AND restart the service, which clears the ban and the failure counter.
for ip in $(docker exec "$NODE" fail2ban-client get sshd banned 2>/dev/null \
    | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); do
  docker exec "$NODE" fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1
done
docker exec "$NODE" systemctl restart fail2ban 2>/dev/null
recovered=0
for _ in $(seq 1 8); do
  sleep 2
  if ssh "${OPTS[@]}" -i "$GOOD" opsadmin@127.0.0.1 true >/dev/null 2>&1; then
    recovered=1; break
  fi
done
[ "$recovered" = 1 ] && echo "  [OK] after unban + restart, opsadmin logs in again" \
                     || echo "  [??] admin still cannot log in after recovery"

echo
echo "=============================================================="
echo " Attacks repelled: $blocked   |   Leaks: $leaked"
echo "=============================================================="
[ "$leaked" -eq 0 ] && echo "The hardening held. No unauthorized access." \
                    || { echo "SECURITY LEAK — see [!! LEAK] lines above."; exit 1; }
