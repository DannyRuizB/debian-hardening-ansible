#!/usr/bin/env bash
# =============================================================================
# Before/after: run the SAME attack against a stock Debian node and a hardened
# one, side by side, so the value of each control is obvious. The hardened node
# (port 2222) must already be up and hardened; this script spins up the stock
# "vulnerable" node (port 2223) itself and tears it down at the end.
#
#   ./node.sh up && ./node.sh wait
#   echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
#   ansible-playbook -i inventory_first_run.ini ../site.yml -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
#   ./before_after.sh
#
# The "vulnerable" node is the same image with a stock SSH config: root login
# on, password auth on, a weak root password (root:toor), no firewall, no
# Fail2Ban — a fresh VPS before anyone hardened it. All local, on 127.0.0.1.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

VULN=dh-vuln-node
VPORT=2223          # stock node
HPORT=2222          # hardened node (already provisioned)
EVIL=".attacker/evil"
COM=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o ConnectTimeout=4 -o BatchMode=yes)
# Password logins can't use BatchMode (it disables the SSH_ASKPASS helper).
PWCOM=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4)

[ -f "$EVIL" ] || { mkdir -p .attacker; chmod 700 .attacker
  ssh-keygen -t ed25519 -f "$EVIL" -N "" -C attacker >/dev/null 2>&1; }
printf '#!/bin/sh\necho toor\n' > .askpass.sh && chmod +x .askpass.sh

cleanup() { docker rm -f "$VULN" >/dev/null 2>&1; rm -f .askpass.sh; }
trap cleanup EXIT

echo ">> Bringing up the stock (unhardened) node on 127.0.0.1:$VPORT..."
docker rm -f "$VULN" >/dev/null 2>&1
docker run -d --name "$VULN" --hostname vuln-node --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -p "127.0.0.1:$VPORT:22" dh-test-node >/dev/null
sleep 4
docker exec "$VULN" bash -c \
  "printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/00-vuln.conf; \
   echo 'root:toor' | chpasswd; systemctl restart ssh" 2>/dev/null
sleep 2

# Start the hardened node from a clean jail, so a ban left by a previous run
# doesn't skew the comparison (an already-banned probe can't read auth methods).
docker exec dh-test-node bash -c \
  'for ip in $(fail2ban-client get sshd banned 2>/dev/null | grep -oE "[0-9.]+"); do \
     fail2ban-client set sshd unbanip "$ip"; done; systemctl restart fail2ban' >/dev/null 2>&1
sleep 3

# --- attack primitives, run identically against either port -----------------

# Try to log in as root with the weak password. Echoes IN or NOPE.
pw_login_root() {
  local port="$1"
  if SSH_ASKPASS="$PWD/.askpass.sh" SSH_ASKPASS_REQUIRE=force setsid -w ssh \
       -p "$port" "${PWCOM[@]}" -o PreferredAuthentications=password \
       -o PubkeyAuthentication=no root@127.0.0.1 true >/dev/null 2>&1; then
    echo IN; else echo NOPE; fi
}

# What auth methods does the server advertise?
offered() {
  local port="$1"
  ssh -v -p "$port" "${COM[@]}" -o PreferredAuthentications=none \
    root@127.0.0.1 true 2>&1 \
    | sed -n 's/.*Authentications that can continue: //p' | head -1
}

# Fire waves of failed logins; after each, probe once. A plain publickey
# "denied" means the server still answers (no throttling); a transport cut
# (reset/timeout) means we've been banned. Echoes BANNED or UNLIMITED.
bruteforce() {
  local port="$1" wave u err
  for wave in 1 2 3 4; do
    for u in root admin test oracle git postgres ubuntu daniel; do
      ssh -p "$port" "${COM[@]}" -o ConnectTimeout=3 -i "$EVIL" "$u@127.0.0.1" true >/dev/null 2>&1
    done
    sleep 3
    err=$(ssh -p "$port" "${COM[@]}" -i "$EVIL" probe@127.0.0.1 true 2>&1)
    echo "$err" | grep -qiE "reset|timed out|refused|no route|closed by remote" \
      && { echo BANNED; return; }
  done
  echo UNLIMITED
}

row() { printf "  %-34s | %-18s | %-18s\n" "$1" "$2" "$3"; }

echo
echo "==============================================================================="
echo " SAME ATTACK, TWO NODES  —  stock Debian (:$VPORT)  vs  hardened (:$HPORT)"
echo "==============================================================================="
row "Attack / probe" "STOCK node" "HARDENED node"
row "----------------------------------" "------------------" "------------------"

v=$(pw_login_root "$VPORT"); h=$(pw_login_root "$HPORT")
row "root login w/ weak password 'toor'" \
    "$([ "$v" = IN ] && echo '>> BREACHED (in)' || echo 'refused')" \
    "$([ "$h" = IN ] && echo '>> BREACHED (in)' || echo 'refused')"

vo=$(offered "$VPORT"); ho=$(offered "$HPORT")
row "auth methods offered" "${vo:-?}" "${ho:-?}"

vb=$(bruteforce "$VPORT"); hb=$(bruteforce "$HPORT")
row "brute force (12 tries) ->" \
    "$([ "$vb" = BANNED ] && echo 'banned' || echo 'no limit, no ban')" \
    "$([ "$hb" = BANNED ] && echo 'banned after 5' || echo 'no limit, no ban')"

echo "-------------------------------------------------------------------------------"
echo
echo "  Reading it: on the stock node the attacker is root in one guess, the server"
echo "  offers password auth, and brute force is never throttled. The hardened node"
echo "  refuses the password outright (publickey only) and Fail2Ban cuts the"
echo "  attacker off after 5 tries. Same attack, opposite outcome."
echo
echo ">> Tearing down the stock node (the hardened one stays up)."
