#!/usr/bin/env bash
# =============================================================================
# Compliance audit: score the hardened node against a CIS-style checklist.
# Unlike verify.sh (which confirms the baseline was applied) this grades a
# WIDER set of best practices — including ones the baseline doesn't cover yet —
# so the score is honest and the failures are a to-do list, not a victory lap.
#
# Run it on an already-hardened node:
#   ./node.sh up && ./node.sh wait && <harden with site.yml> && ./audit.sh
#
# PASS = control in place | WARN = CIS hardening not applied (improvable)
# FAIL = a core security control is missing (serious).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
NODE=dh-test-node

pass=0; warn=0; fail=0
P() { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
W() { printf "  \033[33mWARN\033[0m  %s\n         -> %s\n" "$1" "$2"; warn=$((warn+1)); }
F() { printf "  \033[31mFAIL\033[0m  %s\n         -> %s\n" "$1" "$2"; fail=$((fail+1)); }

# Cache the effective SSH config once; val <key> returns the effective value.
sshd_conf=$(docker exec "$NODE" sshd -T 2>/dev/null)
val() { echo "$sshd_conf" | awk -v k="$1" 'tolower($1)==k{print $2; exit}'; }
on_node() { docker exec "$NODE" "$@" 2>/dev/null; }

echo "============================================================="
echo " COMPLIANCE AUDIT — hardened node vs a CIS-style checklist"
echo "============================================================="

echo "-- SSH: authentication (core) -------------------------------"
[ "$(val permitrootlogin)" = no ] \
  && P "Root SSH login disabled" \
  || F "Root SSH login allowed" "set PermitRootLogin no"
[ "$(val passwordauthentication)" = no ] \
  && P "Password authentication disabled" \
  || F "Password authentication enabled" "set PasswordAuthentication no"
[ "$(val pubkeyauthentication)" = yes ] \
  && P "Public-key authentication enabled" \
  || F "Public-key authentication off" "set PubkeyAuthentication yes"
[ "$(val kbdinteractiveauthentication)" = no ] \
  && P "Keyboard-interactive auth disabled" \
  || W "Keyboard-interactive auth enabled" "set KbdInteractiveAuthentication no"
[ "$(val permitemptypasswords)" = no ] \
  && P "Empty passwords rejected" \
  || F "Empty passwords permitted" "set PermitEmptyPasswords no"

echo "-- SSH: hardening extras (CIS) ------------------------------"
[ "$(val maxauthtries)" -le 4 ] 2>/dev/null \
  && P "MaxAuthTries <= 4 ($(val maxauthtries))" \
  || W "MaxAuthTries is $(val maxauthtries) (CIS: <= 4)" "add 'MaxAuthTries 4' to the drop-in"
[ "$(val x11forwarding)" = no ] \
  && P "X11 forwarding disabled" \
  || W "X11 forwarding enabled" "add 'X11Forwarding no' to the drop-in"
[ "$(val logingracetime)" -le 60 ] 2>/dev/null \
  && P "LoginGraceTime <= 60 ($(val logingracetime))" \
  || W "LoginGraceTime is $(val logingracetime)s (CIS: <= 60)" "add 'LoginGraceTime 60'"
[ "$(val clientaliveinterval)" -ge 1 ] 2>/dev/null && [ "$(val clientaliveinterval)" -le 300 ] 2>/dev/null \
  && P "Idle sessions time out (ClientAliveInterval $(val clientaliveinterval))" \
  || W "No idle-session timeout (ClientAliveInterval $(val clientaliveinterval))" "add 'ClientAliveInterval 300'"

echo "-- Firewall -------------------------------------------------"
on_node ufw status | grep -q "Status: active" \
  && P "Host firewall (UFW) active" \
  || F "UFW inactive" "enable ufw"
on_node ufw status verbose | grep -q "deny (incoming)" \
  && P "Default policy denies incoming" \
  || F "Incoming not default-denied" "ufw default deny incoming"

echo "-- Intrusion prevention -------------------------------------"
[ "$(on_node systemctl is-active fail2ban)" = active ] \
  && P "Fail2Ban running" \
  || F "Fail2Ban not running" "enable+start fail2ban"
on_node fail2ban-client status sshd | grep -q "Currently banned" \
  && P "sshd jail active" \
  || F "sshd jail missing" "enable the [sshd] jail"

echo "-- Patch management -----------------------------------------"
[ "$(on_node systemctl is-active unattended-upgrades)" = active ] \
  && P "unattended-upgrades running" \
  || F "unattended-upgrades not running" "enable it"
on_node grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades \
  && P "Automatic security updates enabled" \
  || F "Automatic updates not configured" "set APT::Periodic::Unattended-Upgrade 1"

echo "-- Accounts & files -----------------------------------------"
on_node getent group sudo | grep -qE ':.*[a-z]' \
  && P "A non-root sudo account exists ($(on_node getent group sudo | sed 's/.*://'))" \
  || W "No non-root sudo account found" "create an admin user (admin_user role)"
empty=$(on_node awk -F: '($2==""){print $1}' /etc/shadow | tr '\n' ' ')
[ -z "$empty" ] \
  && P "No accounts with an empty password" \
  || F "Accounts with empty password: $empty" "lock or set passwords"
perm=$(on_node stat -c '%a' /etc/ssh/sshd_config)
[ "$perm" = 600 ] || [ "$perm" = 644 ] \
  && P "sshd_config permissions sane ($perm)" \
  || W "sshd_config is $perm" "chmod 600 /etc/ssh/sshd_config"

echo "============================================================="
total=$((pass + warn + fail))
score=$(awk "BEGIN{printf \"%.0f\", ($pass + $warn*0.5) / $total * 100}")
echo " Score: $pass PASS, $warn WARN, $fail FAIL  ->  ${score}% compliant"
if [ "$fail" -gt 0 ]; then
  echo " Verdict: core controls MISSING — fix the FAIL items first."
elif [ "$warn" -gt 0 ]; then
  echo " Verdict: core baseline solid; WARN items are CIS hardening still on the"
  echo "          table (extra sshd_config directives the drop-in could set)."
else
  echo " Verdict: fully compliant with this checklist."
fi
echo "============================================================="
