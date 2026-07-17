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
# Effective kernel value for a sysctl key (empty if the key doesn't exist).
sctl() { docker exec "$NODE" sysctl -n "$1" 2>/dev/null; }

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

echo "-- SSH: session policies (CIS 5.2) --------------------------"
[ "$(val allowtcpforwarding)" = no ] \
  && P "TCP forwarding disabled (no pivoting through the host)" \
  || W "TCP forwarding enabled" "add 'AllowTcpForwarding no' (ssh_policies role)"
[ "$(val allowagentforwarding)" = no ] \
  && P "Agent forwarding disabled" \
  || W "Agent forwarding enabled" "add 'AllowAgentForwarding no'"
[ "$(val maxsessions)" -le 10 ] 2>/dev/null \
  && P "MaxSessions capped ($(val maxsessions))" \
  || W "MaxSessions is $(val maxsessions) (CIS: <= 10)" "add 'MaxSessions 4'"
echo "$sshd_conf" | grep -q '^maxstartups 10:30:60' \
  && P "MaxStartups throttled (10:30:60)" \
  || W "MaxStartups is $(val maxstartups)" "add 'MaxStartups 10:30:60'"
[ "$(val loglevel)" = VERBOSE ] \
  && P "LogLevel VERBOSE (logins log the key fingerprint)" \
  || W "LogLevel is $(val loglevel)" "add 'LogLevel VERBOSE'"
[ "$(val permituserenvironment)" = no ] \
  && P "User environment not honored at login" \
  || W "PermitUserEnvironment enabled" "add 'PermitUserEnvironment no'"
[ "$(val hostbasedauthentication)" = no ] \
  && P "Host-based authentication disabled" \
  || W "Host-based auth enabled" "add 'HostbasedAuthentication no'"
[ "$(val ignorerhosts)" = yes ] \
  && P "Legacy rhosts files ignored" \
  || W "rhosts honored" "add 'IgnoreRhosts yes'"

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

echo "-- Kernel parameters (CIS network) --------------------------"
[ "$(sctl net.ipv4.conf.all.accept_redirects)" = 0 ] \
  && P "ICMP redirects not accepted" \
  || W "ICMP redirects accepted" "set net.ipv4.conf.all.accept_redirects=0"
[ "$(sctl net.ipv4.conf.all.send_redirects)" = 0 ] \
  && P "ICMP redirects not sent" \
  || W "ICMP redirects sent" "set net.ipv4.conf.all.send_redirects=0"
[ "$(sctl net.ipv4.conf.all.accept_source_route)" = 0 ] \
  && P "Source-routed packets refused" \
  || W "Source routing accepted" "set net.ipv4.conf.all.accept_source_route=0"
[ "$(sctl net.ipv4.conf.all.rp_filter)" = 1 ] \
  && P "Reverse-path filtering on" \
  || W "Reverse-path filtering off" "set net.ipv4.conf.all.rp_filter=1"
[ "$(sctl net.ipv4.tcp_syncookies)" = 1 ] \
  && P "SYN cookies enabled" \
  || W "SYN cookies disabled" "set net.ipv4.tcp_syncookies=1"
[ "$(sctl kernel.dmesg_restrict)" = 1 ] \
  && P "dmesg restricted to root" \
  || W "dmesg world-readable" "set kernel.dmesg_restrict=1"
[ "$(sctl fs.suid_dumpable)" = 0 ] \
  && P "setuid programs can't dump core" \
  || W "setuid core dumps allowed" "set fs.suid_dumpable=0"

echo "-- Account policies (CIS) -----------------------------------"
# Value of a key in /etc/login.defs (empty if the key is absent/commented).
ld() { on_node awk -v k="$1" '$1==k{print $2; exit}' /etc/login.defs; }
[ "$(ld PASS_MAX_DAYS)" -le 365 ] 2>/dev/null \
  && P "Password max age <= 365 days ($(ld PASS_MAX_DAYS))" \
  || W "Password max age is $(ld PASS_MAX_DAYS)" "set PASS_MAX_DAYS 365 in /etc/login.defs"
[ "$(ld PASS_MIN_DAYS)" -ge 1 ] 2>/dev/null \
  && P "Password min age >= 1 day ($(ld PASS_MIN_DAYS))" \
  || W "Password min age is $(ld PASS_MIN_DAYS)" "set PASS_MIN_DAYS 1 in /etc/login.defs"
[ "$(ld PASS_WARN_AGE)" -ge 7 ] 2>/dev/null \
  && P "Password expiry warning >= 7 days ($(ld PASS_WARN_AGE))" \
  || W "Expiry warning is $(ld PASS_WARN_AGE)" "set PASS_WARN_AGE 7 in /etc/login.defs"
inactive=$(on_node useradd -D | sed -n 's/^INACTIVE=//p')
[ "$inactive" -ge 0 ] 2>/dev/null && [ "$inactive" -le 30 ] 2>/dev/null \
  && P "New accounts lock after <= 30 days of inactivity (INACTIVE=$inactive)" \
  || W "Inactivity lock is INACTIVE=${inactive:--1} (never)" "run 'useradd -D -f 30'"

echo "-- Filesystem mount options (CIS) ---------------------------"
# Live options of /dev/shm (empty if it isn't a mountpoint).
shm_opts=$(on_node findmnt -no OPTIONS /dev/shm)
for opt in nodev nosuid noexec; do
  case ",$shm_opts," in
    *",$opt,"*) P "/dev/shm mounted with $opt";;
    *) W "/dev/shm is missing $opt" "remount /dev/shm with $opt (mount_options role)";;
  esac
done
on_node grep -qE '^[^#].*[[:space:]]/dev/shm[[:space:]].*nodev' /etc/fstab \
  && P "/dev/shm options pinned in fstab (survive reboots)" \
  || W "/dev/shm options not in fstab" "pin 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'"

echo "-- Warning banners (CIS 1.7) --------------------------------"
[ "$(val banner)" != "none" ] && [ -n "$(val banner)" ] \
  && P "sshd presents a pre-auth banner ($(val banner))" \
  || W "sshd has no pre-auth banner" "set Banner /etc/issue.net (banners role)"
on_node grep -Eq '\\[mrsv]|Debian|Ubuntu' /etc/issue \
  && W "/etc/issue leaks OS/kernel info" "replace with a plain legal notice" \
  || P "/etc/issue has no OS/kernel leak"
on_node grep -Eq '\\[mrsv]|Debian|Ubuntu' /etc/issue.net \
  && W "/etc/issue.net leaks OS/kernel info" "replace with a plain legal notice" \
  || P "/etc/issue.net has no OS/kernel leak"
perm_issue=$(on_node stat -c '%a %U %G' /etc/issue.net)
[ "$perm_issue" = "644 root root" ] \
  && P "banner file permissions sane (644 root:root)" \
  || W "issue.net is $perm_issue" "chown root:root && chmod 644"

echo "-- Sudo hardening (CIS 5.3) ---------------------------------"
on_node dpkg -s sudo >/dev/null \
  && P "sudo is installed" \
  || F "sudo is not installed" "apt-get install sudo"
on_node grep -rqE '^Defaults\s+use_pty' /etc/sudoers /etc/sudoers.d \
  && P "sudo runs commands in their own pty (use_pty)" \
  || W "use_pty not set" "add 'Defaults use_pty' (sudo_hardening role)"
on_node grep -rqE '^Defaults\s+logfile=' /etc/sudoers /etc/sudoers.d \
  && P "sudo has a dedicated logfile" \
  || W "sudo logs only via syslog" "add 'Defaults logfile=\"/var/log/sudo.log\"'"
sudoers_perm=$(on_node stat -c '%a' /etc/sudoers.d/99-hardening-sudo 2>/dev/null)
[ "$sudoers_perm" = "440" ] \
  && P "sudo drop-in permissions sane (440)" \
  || W "sudo drop-in is ${sudoers_perm:-absent}" "mode 0440 (sudo_hardening role)"

echo "-- Core dumps (CIS 1.5) -------------------------------------"
on_node grep -rqE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d \
  && P "hard core limit 0 for all users" \
  || W "no '* hard core 0' limit" "add a limits.d drop-in (coredump_limits role)"
on_node grep -rqE '^root[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d \
  && P "root has its own hard core 0 line ('*' never matches root)" \
  || W "root can still dump core" "add 'root hard core 0' (coredump_limits role)"
on_node grep -rqsE '^Storage=none' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d \
  && P "systemd-coredump storage disabled (Storage=none)" \
  || W "systemd-coredump would still store dumps" "set Storage=none (coredump_limits role)"
on_node grep -rqsE '^ProcessSizeMax=0' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d \
  && P "systemd-coredump processing capped (ProcessSizeMax=0)" \
  || W "systemd-coredump would still process dumps" "set ProcessSizeMax=0 (coredump_limits role)"

echo "-- Umask & shell timeout (CIS 5.4) --------------------------"
umask_defs=$(on_node grep -E '^UMASK[[:space:]]' /etc/login.defs | awk '{print $2}')
[ "$umask_defs" = "027" ] || [ "$umask_defs" = "077" ] \
  && P "login.defs UMASK is restrictive ($umask_defs)" \
  || W "login.defs UMASK is ${umask_defs:-unset}" "set UMASK 027 (umask_tmout role)"
on_node grep -rqsE '^umask[[:space:]]+0?27' /etc/profile.d \
  && P "profile.d sets umask 027 for login shells" \
  || W "no profile.d umask drop-in" "add umask 027 (umask_tmout role)"
tmout_val=$(on_node grep -rhsE '^readonly TMOUT=' /etc/profile.d | head -1 | cut -d= -f2)
[ -n "$tmout_val" ] && [ "$tmout_val" -le 900 ] 2>/dev/null \
  && P "shell timeout set and readonly (TMOUT=$tmout_val)" \
  || W "no readonly TMOUT in profile.d" "add readonly TMOUT=900 (umask_tmout role)"
on_node grep -rqsE '^export TMOUT' /etc/profile.d \
  && P "TMOUT is exported to the session" \
  || W "TMOUT not exported" "add export TMOUT (umask_tmout role)"

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
