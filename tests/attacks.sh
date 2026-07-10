#!/usr/bin/env bash
# =============================================================================
# Attack catalogue: a tour of the reconnaissance and login techniques an
# attacker runs against an SSH box, each one aimed at the hardened node so you
# can see what it gives away (little) and what it refuses (everything that
# matters). Companion to redteam.sh — that one proves the box holds; this one
# walks the toolkit and the defensive lesson behind each move.
#
# Run it on an already-hardened node:
#   ./node.sh up && ./node.sh wait && <harden with site.yml> && ./attacks.sh
#
# All local: recon hits the node's Docker-network IP, logins hit 127.0.0.1:2222.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

NODE=dh-test-node
PORT=2222
EVIL=".attacker/evil"
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE" 2>/dev/null)
COM=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o ConnectTimeout=4 -o BatchMode=yes)

[ -f "$EVIL" ] || { mkdir -p .attacker; chmod 700 .attacker
  ssh-keygen -t ed25519 -f "$EVIL" -N "" -C attacker >/dev/null 2>&1; }

hr() { printf '%s\n' "-------------------------------------------------------------"; }
echo "============================================================="
echo " ATTACK CATALOGUE — recon & login techniques vs the hardened node"
echo " Target: $IP (recon) / 127.0.0.1:$PORT (SSH)"
echo "============================================================="

hr; echo " 1. Banner grabbing   (passive recon)"; hr
echo "  What the attacker learns from the SSH greeting:"
banner=$(timeout 4 bash -c "exec 3<>/dev/tcp/$IP/22; head -1 <&3" 2>/dev/null)
echo "    $banner"
echo "  Lesson: the version leaks, which lets an attacker look up CVEs. Hiding"
echo "  it is only obscurity — the real defence is staying patched, which is"
echo "  what the unattended_upgrades role does."

hr; echo " 2. Port scan   (active recon — attack surface)"; hr
echo "  Which doors are open? (common service ports)"
for p in 21 22 23 25 80 443 3306 5432 8080; do
  if timeout 3 nc -z -w2 "$IP" "$p" 2>/dev/null; then
    printf "    %-5s OPEN\n" "$p"
  else
    printf "    %-5s filtered (UFW drops it)\n" "$p"
  fi
done
echo "  Lesson: UFW default-deny means only port 22 answers. Every closed port"
echo "  is one less service to attack."

hr; echo " 3. Username enumeration   (does the server leak valid accounts?)"; hr
echo "  A weak server answers differently for real vs fake users. Compare:"
for u in opsadmin root nonexistent_xyz; do
  reply=$(ssh -p "$PORT" "${COM[@]}" -i "$EVIL" "$u@127.0.0.1" true 2>&1 \
          | grep -iE "permission denied|authentication" | head -1)
  printf "    %-18s -> %s\n" "$u" "${reply:-<no distinguishing reply>}"
done
echo "  Lesson: every account — real, root, or made-up — gets the identical"
echo "  'Permission denied (publickey)'. sshd leaks nothing to enumerate."

hr; echo " 4. Dictionary / credential attack   (guessing passwords)"; hr
echo "  Throwing a common-password list at root and admin:"
printf '#!/bin/sh\necho "$ATTACK_PW"\n' > .askpass.sh && chmod +x .askpass.sh
hits=0; tries=0
for user in root admin; do
  for pw in 123456 password root toor admin qwerty 12345678 letmein; do
    tries=$((tries + 1))
    if ATTACK_PW="$pw" SSH_ASKPASS="$PWD/.askpass.sh" SSH_ASKPASS_REQUIRE=force \
        setsid -w ssh -p "$PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "$user@127.0.0.1" true >/dev/null 2>&1; then
      echo "    >> CRACKED $user:$pw"; hits=$((hits + 1))
    fi
  done
done
rm -f .askpass.sh
echo "    tried $tries passwords, cracked $hits"
echo "  Lesson: with PasswordAuthentication off the server never even reads the"
echo "  password — the whole dictionary is dead on arrival. (On a stock node"
echo "  with password auth, this same list is exactly how boxes get owned.)"

hr; echo " Recon toolkit summary"; hr
cat <<EOF
    Banner grab   -> version -> known CVEs        | mitigated by: patching
    Port scan     -> open services -> surface     | mitigated by: UFW deny
    User enum     -> valid accounts to target     | mitigated by: key-only sshd
    Dictionary    -> weak passwords -> shell       | mitigated by: no password auth
EOF
echo "============================================================="
