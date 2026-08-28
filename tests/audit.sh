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

echo "-- SSH: crypto policy (CIS 5.2) -----------------------------"
# What sshd will actually NEGOTIATE — a weak MAC in this list is offered to
# every client that asks, and only bites with a non-AEAD (ctr) cipher, which
# stock keeps in its list too.
case "$(val macs)" in
  *sha1*|*umac-64*) W "sshd still offers sha1 or 64-bit-tag MACs" "pin MACs to sha2-etm/umac-128-etm (ssh_crypto role)" ;;
  *)                P "MACs are etm-only, 128-bit tags or better (no sha1)" ;;
esac
case "$(val kexalgorithms)" in
  *sha1*|*ecdh-sha2-nistp*) W "key exchange still offers NIST P-curves or sha1" "pin KexAlgorithms to the PQ hybrids + curve25519 (ssh_crypto role)" ;;
  *mlkem768*|*sntrup761*)   P "key exchange is PQ-hybrid + curve25519 only" ;;
  *)                        W "key exchange has no post-quantum hybrid" "pin KexAlgorithms (ssh_crypto role)" ;;
esac
case "$(val ciphers)" in
  *cbc*) F "sshd still offers CBC-mode ciphers" "pin Ciphers to AEAD + ctr (ssh_crypto role)" ;;
  *)     P "Ciphers are AEAD/ctr only (no CBC)" ;;
esac

echo "-- Legacy protocol packages (CIS 2.2/2.3) --------------------"
# dpkg state on the node: installed or config-files both count as present.
legacy_check() {
  local found="" p st
  for p in $2; do
    st=$(on_node dpkg-query -W -f '${db:Status-Status}' "$p") || true
    case "$st" in installed|config-files) found="$found $p";; esac
  done
  echo "$found"
}
srv_found=$(legacy_check servers "telnetd inetutils-telnetd rsh-server rsh-redone-server talkd inetutils-talkd tftpd atftpd tftpd-hpa xinetd openbsd-inetd inetutils-inetd")
[ -z "$srv_found" ] \
  && P "No legacy protocol server installed (telnetd/rshd/talkd/tftpd/inetd family)" \
  || F "Legacy protocol servers present:$srv_found" "purge them (legacy_protocols role)"
cli_found=$(legacy_check clients "telnet inetutils-telnet rsh-client rsh-redone-client talk inetutils-talk tftp atftp tftp-hpa")
[ -z "$cli_found" ] \
  && P "No legacy cleartext client installed (telnet/rsh/talk/tftp family)" \
  || W "Legacy cleartext clients present:$cli_found" "run the legacy_protocols role"
nis_st=$(on_node dpkg-query -W -f '${db:Status-Status}' nis) || true
case "$nis_st" in
  installed|config-files) F "NIS is installed" "purge nis (legacy_protocols role)";;
  *) P "NIS is not installed (nobody serves the password map)";;
esac

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

echo "-- Cron restrictions (CIS 5.1) ------------------------------"
crontab_perm=$(on_node stat -c '%a %U %G' /etc/crontab)
[ "$crontab_perm" = "600 root root" ] \
  && P "/etc/crontab is 600 root:root" \
  || W "/etc/crontab is ${crontab_perm:-missing}" "chmod 600, chown root:root (cron_restrictions role)"
cron_dirs=$(on_node bash -c 'stat -c "%a %U %G" /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>/dev/null | sort -u')
[ "$cron_dirs" = "700 root root" ] \
  && P "cron drop-in directories are 700 root:root" \
  || W "cron dirs are not uniformly 700 root:root" "chmod 700, chown root:root (cron_restrictions role)"
if on_node test -f /etc/cron.allow && [ "$(on_node stat -c '%a %U %G' /etc/cron.allow)" = "640 root root" ]; then
  P "cron.allow exists, 640 root:root (allow-list model)"
else
  W "no root-only cron.allow" "write cron.allow with just root, 640 (cron_restrictions role)"
fi
if on_node test -e /etc/cron.deny; then
  W "cron.deny still present (deny-list model)" "remove it; the allow-list replaces it"
else
  P "cron.deny removed (allow-list replaces the deny-list)"
fi

echo "-- Password policy (CIS 5.3/5.4) ----------------------------"
on_node grep -q pam_pwquality /etc/pam.d/common-password \
  && P "pam_pwquality gates every password change" \
  || W "pam_pwquality not wired into common-password" "apt install libpam-pwquality (password_policy role)"
minlen=$(on_node grep -E '^minlen' /etc/security/pwquality.conf | tr -dc '0-9')
[ "${minlen:-0}" -ge 14 ] 2>/dev/null \
  && P "Password minimum length >= 14 ($minlen)" \
  || W "pwquality minlen is ${minlen:-unset}" "set minlen = 14 in pwquality.conf (password_policy role)"
on_node grep -qE '^enforce_for_root' /etc/security/pwquality.conf \
  && P "Quality policy binds root too (enforce_for_root)" \
  || W "root bypasses the quality policy" "add enforce_for_root to pwquality.conf (password_policy role)"
em=$(ld ENCRYPT_METHOD)
case "${em:-}" in
  YESCRYPT|yescrypt|SHA512|sha512) P "Password hashing pinned to a strong crypt ($em)";;
  *) W "ENCRYPT_METHOD is ${em:-unset}" "pin ENCRYPT_METHOD YESCRYPT in login.defs (password_policy role)";;
esac

echo "-- File integrity (AIDE, CIS 1.4) ---------------------------"
on_node test -f /etc/aide/hardening.conf \
  && P "AIDE config present" \
  || W "no AIDE config" "install aide + baseline (aide role)"
on_node test -s /var/lib/aide/hardening.db \
  && P "AIDE baseline database built" \
  || W "no AIDE baseline database" "run aide --init (aide role)"
[ "$(on_node systemctl is-enabled aide-check.timer 2>/dev/null)" = enabled ] \
  && P "Daily AIDE check timer enabled" \
  || W "no daily AIDE check timer" "enable aide-check.timer (aide role)"

echo "-- Rootkit detection (rkhunter) -----------------------------"
on_node test -x /usr/bin/rkhunter \
  && P "rkhunter installed" \
  || W "rkhunter not installed" "apt install rkhunter (rkhunter role)"
on_node test -s /var/lib/rkhunter/db/rkhunter.dat \
  && P "rkhunter property baseline present" \
  || W "no rkhunter property baseline" "run rkhunter --propupd (rkhunter role)"
[ "$(on_node systemctl is-enabled rkhunter-check.timer 2>/dev/null)" = enabled ] \
  && P "Daily rkhunter check timer enabled" \
  || W "no daily rkhunter check timer" "enable rkhunter-check.timer (rkhunter role)"

echo "-- Kernel module blacklist ----------------------------------"
on_node test -f /etc/modprobe.d/99-hardening-blacklist.conf \
  && P "modprobe blacklist drop-in present" \
  || W "no modprobe blacklist drop-in" "run the module_blacklist role (CIS 1.1.1/3.4)"
fs_count=$(on_node grep -c '^install \(cramfs\|freevxfs\|jffs2\|hfs\|hfsplus\|udf\) /bin/false' /etc/modprobe.d/99-hardening-blacklist.conf || true)
fs_count=${fs_count:-0}
[ "$fs_count" = "6" ] \
  && P "Rare filesystems unloadable (cramfs freevxfs jffs2 hfs hfsplus udf)" \
  || W "rare filesystems still loadable ($fs_count/6 covered)" "install <fs> /bin/false in modprobe.d (CIS 1.1.1)"
proto_count=$(on_node grep -c '^install \(dccp\|sctp\|rds\|tipc\) /bin/false' /etc/modprobe.d/99-hardening-blacklist.conf || true)
proto_count=${proto_count:-0}
[ "$proto_count" = "4" ] \
  && P "Uncommon network protocols unloadable (dccp sctp rds tipc)" \
  || W "uncommon protocols still loadable ($proto_count/4 covered)" "install <proto> /bin/false in modprobe.d (CIS 3.4)"
# Dry run consults the config without touching the kernel: with the install
# directive it prints `install /bin/false`; without it, it errors out.
on_node modprobe -n -v dccp 2>/dev/null | grep -q 'install /bin/false' \
  && P "modprobe honours the blacklist (dccp dry-run runs /bin/false)" \
  || W "modprobe does not defeat dccp" "check the install directive (module_blacklist role)"

echo "-- Account lockout (pam_faillock) ---------------------------"
on_node grep -qE '^deny[[:space:]]*=[[:space:]]*[1-5]$' /etc/security/faillock.conf \
  && P "faillock locks after <= 5 failed attempts" \
  || W "no faillock deny threshold <= 5" "set deny = 5 in /etc/security/faillock.conf (faillock role)"
on_node grep -qE '^unlock_time[[:space:]]*=[[:space:]]*[0-9]+' /etc/security/faillock.conf \
  && P "faillock sets an unlock_time ($(on_node grep '^unlock_time' /etc/security/faillock.conf | tr -d ' '))" \
  || W "no faillock unlock_time" "set unlock_time = 900 (faillock role)"
on_node grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth \
  && P "pam_faillock preauth gate wired into common-auth" \
  || W "pam_faillock not active in common-auth" "run the faillock role (pam-auth-update profiles)"

echo "-- File permissions (CIS 6.1) -------------------------------"
on_node stat -c '%a %U %G' /etc/passwd | grep -q '^644 root root$' \
  && P "/etc/passwd is 644 root:root" \
  || W "/etc/passwd modes are loose" "chown root:root + chmod 644 (file_permissions role)"
on_node stat -c '%a %U %G' /etc/shadow | grep -qE '^(0|600|640) root (root|shadow)$' \
  && P "/etc/shadow is 640 root:shadow or stricter" \
  || W "/etc/shadow modes are loose" "chown root:shadow + chmod 640 (file_permissions role)"
ww_count=$(on_node bash -c 'find / -xdev \( -path /tmp -o -path /var/tmp \) -prune -o -type f -perm -0002 -print 2>/dev/null | wc -l')
[ "${ww_count:-1}" = "0" ] \
  && P "No world-writable files outside scratch dirs" \
  || W "world-writable files present ($ww_count)" "chmod o-w them (file_permissions role)"
orphan_count=$(on_node bash -c 'find / -xdev \( -path /tmp -o -path /var/tmp \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l')
[ "${orphan_count:-1}" = "0" ] \
  && P "No unowned or ungrouped files" \
  || W "orphan files present ($orphan_count)" "chown root:root them (file_permissions role)"

echo "-- SSH access control (CIS 5.2) -----------------------------"
on_node sshd -T 2>/dev/null | grep -qi '^allowgroups ' \
  && P "sshd restricts login to an AllowGroups list ($(on_node sshd -T 2>/dev/null | grep -i '^allowgroups ' | awk '{print $2}'))" \
  || W "sshd has no AllowGroups restriction" "limit SSH login to a group (ssh_access role)"

echo "-- Service sandboxing (systemd) -----------------------------"
on_node systemctl show fail2ban -p NoNewPrivileges 2>/dev/null | grep -q '^NoNewPrivileges=yes$' \
  && P "fail2ban runs with NoNewPrivileges" \
  || W "fail2ban has no NoNewPrivileges" "add a systemd sandboxing drop-in (service_sandboxing role)"
on_node systemctl show fail2ban -p ProtectSystem 2>/dev/null | grep -qE '^ProtectSystem=(full|strict)$' \
  && P "fail2ban has ProtectSystem ($(on_node systemctl show fail2ban -p ProtectSystem 2>/dev/null | cut -d= -f2))" \
  || W "fail2ban filesystem not protected" "set ProtectSystem=full (service_sandboxing role)"

echo "-- Journald persistence (CIS 4.2.2) -------------------------"
on_node bash -c "systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -qE '^Storage=persistent'" \
  && P "journald storage is persistent" \
  || W "journald logs are volatile" "set Storage=persistent (journald role)"
on_node test -d /var/log/journal \
  && P "the persistent journal directory exists" \
  || W "no /var/log/journal" "create it / set Storage=persistent (journald role)"

echo "-- Su restriction (CIS 5.7) ---------------------------------"
on_node grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su \
  && P "su is gated on group membership (pam_wheel use_uid)" \
  || W "su is open to anyone with the password" "gate su on a group with pam_wheel (su_restriction role)"
sugrp=$(on_node getent group sugroup | cut -d: -f4)
if on_node getent group sugroup >/dev/null; then
  [ -z "$sugrp" ] \
    && P "the su group exists and is empty (sudo is the sanctioned path)" \
    || W "the su group has members ($sugrp)" "prefer sudo; keep the group empty unless a user truly needs su"
else
  W "no dedicated su group" "create one and reference it from pam_wheel (su_restriction role)"
fi

echo "-- System accounts (CIS 5.4.2 / 6.2.9) ----------------------"
# A service account with a real shell is a login waiting to happen: a valid
# su target, a valid SSH target while password auth lives, and the landing
# spot after the daemon running as it is compromised. root and the
# sync/shutdown/halt trio are legitimate exceptions.
shelled=$(on_node awk -F: '($3<=999 && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7!="" && $7!~/(nologin|false)$/){print $1}' /etc/passwd | tr '\n' ' ')
[ -z "$shelled" ] \
  && P "no system account has a login shell" \
  || W "system accounts with a login shell ($shelled)" "give them /usr/sbin/nologin (system_accounts role)"
unlocked=$(on_node awk -F: '($2!~/^[!*]/ && $2!=""){print $1}' /etc/shadow | tr '\n' ' ')
sysunlocked=""
for u in $unlocked; do
  [ "$u" = "root" ] && continue
  uid=$(on_node getent passwd "$u" | cut -d: -f3)
  [ -n "$uid" ] && [ "$uid" -le 999 ] 2>/dev/null && sysunlocked="$sysunlocked $u"
done
[ -z "$(printf '%s' "$sysunlocked" | tr -d ' ')" ] \
  && P "every system account password is locked" \
  || W "system accounts with a usable password ($sysunlocked)" "lock them with password_lock (system_accounts role)"

echo "-- Log file permissions (CIS 4.2.3) -------------------------"
# Logs are recon material (auth.log: who logs in from where; dpkg.log: exact
# versions to shop CVEs for — and it ships 644 on stock Debian). Nothing under
# /var/log should be group-writable or world-accessible, except the utmp
# family which is world-readable by design (who/last for non-root users).
leakylogs=$(on_node find /var/log -xdev -type f ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' -perm /0037 | tr '\n' ' ')
[ -z "$(printf '%s' "$leakylogs" | tr -d ' ')" ] \
  && P "no log file is group-writable or world-accessible (utmp family aside)" \
  || W "log files readable/writable beyond owner+group ($leakylogs)" "chmod g-wx,o-rwx (log_permissions role)"
# Tomorrow's logs matter as much as today's: rsyslog must keep creating
# files 0640 (a drifted FileCreateMode rots the sweep on the next rotation).
# (bash -c: `command` is a shell builtin, docker exec can't run it bare)
if on_node bash -c 'command -v rsyslogd' >/dev/null 2>&1; then
  on_node grep -qs '^\$FileCreateMode 0640' /etc/rsyslog.d/99-hardening.conf \
    && P "rsyslog pins FileCreateMode 0640 via the hardening drop-in" \
    || W "rsyslog file-creation mode is not pinned" "write the drop-in (log_permissions role)"
else
  P "rsyslog not installed — journald owns logging (journal files are 640 by design)"
fi

echo "-- Logrotate permissions (CIS 4.4) --------------------------"
# Rotation is the third way a log is born: logrotate's create directive
# decides the mode of every re-created file. Stock Debian's global create is
# bare (clones the old mode, drift included) and dpkg/alternatives ship 644.
if on_node bash -c 'command -v logrotate' >/dev/null 2>&1; then
  on_node grep -Eqs '^create 0640' /etc/logrotate.conf \
    && P "logrotate global create is pinned to 0640 (mode only, owner/group per file)" \
    || W "logrotate global create is bare or loose (rotated logs clone or loosen)" "pin 'create 0640' in logrotate.conf (logrotate_perms role)"
  loosecreate=$(on_node bash -c "grep -RE '^[[:space:]]*create[[:space:]]+0?[0-7]([1-35-7][0-7]|[0-7][1-7])([[:space:]]|\$)' /etc/logrotate.d 2>/dev/null | grep -Ev '^/etc/logrotate.d/(wtmp|btmp):'" | tr '\n' ' ' || true)
  [ -z "$(printf '%s' "$loosecreate" | tr -d ' ')" ] \
    && P "no logrotate.d snippet re-creates logs beyond owner+group (wtmp/btmp keep the utmp split)" \
    || W "logrotate.d snippets re-create logs too open ($loosecreate)" "tighten their create modes (logrotate_perms role)"
else
  P "logrotate not installed — nothing re-creates rotated logs"
fi

# The kernel audit trail: the logging chapter's last piece — journald keeps
# logs, the sweep guards them, logrotate re-creates them right; auditd
# records WHO touched the crown jewels. Configuration is what gets graded
# (a container kernel has no audit netlink, so loaded rules can't be); the
# staged rules activate at boot on real metal.
on_node dpkg -s auditd >/dev/null \
  && P "auditd is installed" \
  || F "auditd is not installed" "apt install auditd (auditd role)"
[ "$(on_node systemctl is-enabled auditd)" = enabled ] \
  && P "auditd is enabled at boot" \
  || F "auditd is not enabled at boot" "systemctl enable auditd (auditd role)"
missingkeys=$(on_node bash -c 'for k in identity scope sshd time-change modules; do grep -qs -- "-k $k" /etc/audit/rules.d/hardening.rules || printf "%s " "$k"; done' || true)
[ -z "$(printf '%s' "$missingkeys" | tr -d ' ')" ] \
  && P "staged audit rules watch identity, sudoers, sshd, time and modules" \
  || F "staged audit rules incomplete (missing: $missingkeys)" "re-run the auditd role"
[ "$(on_node stat -c '%a %U %G' /etc/audit/rules.d/hardening.rules)" = "640 root root" ] \
  && P "the staged audit ruleset is root-only (0640 root:root)" \
  || W "the staged audit ruleset permissions drifted" "chmod 0640 + chown root:root (auditd role)"
on_node grep -Eqs '^max_log_file_action = keep_logs' /etc/audit/auditd.conf \
  && P "audit history is kept, not rotated away (max_log_file_action = keep_logs)" \
  || W "auditd rotates its history away" "pin max_log_file_action = keep_logs (auditd role)"

echo "-- Home directories (CIS 6.2) -------------------------------"
# A 755 home hands every local account a reading pass over ~/.ssh, ~/.aws
# and shell history; the legacy dotfiles below grant access with no password
# at all. Interactive = uid>=1000 with a real shell, plus root.
loose=$(on_node bash -c 'awk -F: '\''($3 >= 1000 && $7 !~ /(nologin|false)$/) || $1 == "root" { print $6 }'\'' /etc/passwd | while read -r h; do [ -d "$h" ] || continue; m=$(stat -c %a "$h"); [ $((8#$m & 8#0027)) -ne 0 ] && echo "$h=$m"; done; true' | tr '\n' ' ' || true)
[ -z "$(printf '%s' "$loose" | tr -d ' ')" ] \
  && P "every interactive home is 750 or tighter (no group-write, no world access)" \
  || W "interactive homes readable beyond owner+group ($loose)" "chmod g-w,o-rwx on each (home_permissions role)"
[ "$(on_node stat -c %a /root)" = "700" ] \
  && P "root's home keeps Debian's 700" \
  || W "root's home has drifted from 700" "chmod 700 /root (home_permissions role)"
relics=$(on_node bash -c 'awk -F: '\''($3 >= 1000 && $7 !~ /(nologin|false)$/) || $1 == "root" { print $6 }'\'' /etc/passwd | while read -r h; do for f in .netrc .rhosts .shosts; do [ -e "$h/$f" ] && echo "$h/$f"; done; done; true' | tr '\n' ' ' || true)
[ -z "$(printf '%s' "$relics" | tr -d ' ')" ] \
  && P "no .netrc / .rhosts / .shosts credential relics in any interactive home" \
  || F "passwordless-access relics present: $relics" "remove them (home_permissions role)"
fwd=$(on_node bash -c 'awk -F: '\''($3 >= 1000 && $7 !~ /(nologin|false)$/) || $1 == "root" { print $6 }'\'' /etc/passwd | while read -r h; do [ -e "$h/.forward" ] && echo "$h/.forward"; done; true' | tr '\n' ' ' || true)
[ -z "$(printf '%s' "$fwd" | tr -d ' ')" ] \
  && P "no .forward files silently rerouting mail" \
  || W ".forward files present: $fwd" "remove them (home_permissions role)"

echo "-- Process isolation ----------------------------------------"
# `ps aux` on a stock box hands every local account a full inventory plus any
# password sitting in someone else's command line; ptrace lets a process read
# another's memory (browser cookies, ssh-agent keys) with no root at all.
on_node findmnt -no OPTIONS /proc | grep -Eq 'hidepid=(2|invisible)' \
  && P "/proc hides other users' processes (hidepid)" \
  || W "/proc shows every user's processes (ps aux leaks command lines)" "remount /proc with hidepid=2 (process_isolation role)"
on_node grep -Eqs '^[^#[:space:]]+[[:space:]]+/proc[[:space:]].*hidepid=' /etc/fstab \
  && P "the hidepid option is pinned in fstab (survives a reboot)" \
  || W "hidepid is not pinned in fstab" "add a /proc line with hidepid (process_isolation role)"
[ "$(sctl kernel.yama.ptrace_scope)" = "1" ] \
  && P "ptrace is restricted to direct parents (yama.ptrace_scope=1)" \
  || W "any process can ptrace another of the same user" "set kernel.yama.ptrace_scope=1 (process_isolation role)"

echo "-- Guess cost (hash cost factor + fail delay) ----------------"
# A stolen shadow file is cracked at the speed of one hash evaluation and a
# live prompt is guessed at the speed of one round-trip — both are knobs.
ycf=$(ld YESCRYPT_COST_FACTOR)
[ "$ycf" = "11" ] \
  && P "yescrypt cost factor at maximum (a guess against a stolen hash costs ~1 s)" \
  || W "yescrypt cost factor is ${ycf:-unset} (stock 5: milliseconds per guess)" "set YESCRYPT_COST_FACTOR 11 in login.defs (guess_cost role)"
fd=$(ld FAIL_DELAY)
if [ -n "$fd" ] && [ "$fd" -ge 4 ] 2>/dev/null; then
  P "failed logins wait ${fd} s before returning (online guessing throttled)"
else
  W "FAIL_DELAY is ${fd:-unset}" "set FAIL_DELAY 5 in login.defs (guess_cost role)"
fi
on_node grep -q pam_faildelay /etc/pam.d/common-auth \
  && P "pam_faildelay is wired into the auth stack" \
  || W "pam_faildelay not wired into common-auth" "enable the hardening-faildelay profile (guess_cost role)"

echo "-- Root PATH integrity (CIS 6.2.8) ---------------------------"
# Whoever can write to a directory early in root's PATH chooses what root
# runs. Three sources set it on Debian and they do not agree: login.defs is
# what CIS names, /etc/profile is what actually wins for a login shell, and
# /etc/crontab is what root's scheduled jobs get.
# `stat -Lc` on purpose: /bin and /sbin are symlinks (always mode 777), so a
# naive check would flag every stock Debian.
path_problems() {  # $1 = a PATH string; echoes the offending entries
  on_node bash -c "printf '%s' '$1' | tr ':' '\n' | while IFS= read -r d; do
      [ -z \"\$d\" ] && { echo 'empty'; continue; }
      case \"\$d\" in /*) ;; *) echo \"relative:\$d\"; continue;; esac
      [ -d \"\$d\" ] || { echo \"missing:\$d\"; continue; }
      m=\$(stat -Lc %a \"\$d\"); case \"\$m\" in *[2367]) echo \"loose:\$d(\$m)\";; esac
    done; true"
}
supath=$(on_node awk '$1=="ENV_SUPATH"{sub(/^[^=]*=/, "", $2); print $2; exit}' /etc/login.defs)
sup_bad=$(path_problems "$supath" | tr '\n' ' ')
[ -z "$(printf '%s' "$sup_bad" | tr -d ' ')" ] \
  && P "login.defs ENV_SUPATH is free of unsafe entries" \
  || W "ENV_SUPATH has unsafe entries: $sup_bad" "drop empty/relative/writable entries (root_path role)"
prof_bad=""
while IFS= read -r p; do
  [ -n "$p" ] || continue
  prof_bad="$prof_bad$(path_problems "$p" | tr '\n' ' ')"
done <<< "$(on_node bash -c "grep -hoE '^[[:space:]]*PATH=\"[^\"]*\"' /etc/profile | sed 's/.*PATH=\"//; s/\"\$//'")"
[ -z "$(printf '%s' "$prof_bad" | tr -d ' ')" ] \
  && P "/etc/profile PATH lines are free of unsafe entries (the file that wins)" \
  || F "/etc/profile PATH has unsafe entries: $prof_bad" "sanitize the PATH lines (root_path role)"
cron_bad=$(path_problems "$(on_node awk -F= '$1=="PATH"{print $2; exit}' /etc/crontab)" | tr '\n' ' ')
[ -z "$(printf '%s' "$cron_bad" | tr -d ' ')" ] \
  && P "/etc/crontab PATH is free of unsafe entries (root's cron jobs)" \
  || W "/etc/crontab PATH has unsafe entries: $cron_bad" "sanitize PATH= in /etc/crontab (root_path role)"

echo "-- Apt updater sandboxing (systemd) -------------------------"
on_node systemctl show apt-daily-upgrade.service -p NoNewPrivileges 2>/dev/null | grep -q '^NoNewPrivileges=yes$' \
  && P "apt updater runs with NoNewPrivileges" \
  || W "apt updater has no NoNewPrivileges" "add a systemd sandboxing drop-in (apt_sandboxing role)"
# The anti-lesson, audited too: these two flags MUST stay off or apt breaks.
on_node systemctl show apt-daily-upgrade.service -p ProtectSystem 2>/dev/null | grep -qE '^ProtectSystem=(full|strict)$' \
  && W "apt updater has ProtectSystem set — dpkg cannot write /usr" "remove ProtectSystem from the drop-in (measured to break apt)" \
  || P "apt updater leaves ProtectSystem off (dpkg must write /usr)"
on_node systemctl show apt-daily-upgrade.service -p RestrictSUIDSGID 2>/dev/null | grep -q '^RestrictSUIDSGID=yes$' \
  && W "apt updater has RestrictSUIDSGID — cannot install setuid binaries" "remove RestrictSUIDSGID from the drop-in (measured to break apt)" \
  || P "apt updater leaves RestrictSUIDSGID off (dpkg installs setuid bins)"

echo "-- Password history (CIS 5.3.3) -----------------------------"
remember=$(on_node bash -c "grep -v '^#' /etc/pam.d/common-password | grep -o 'pam_pwhistory\.so.*' | grep -o 'remember=[0-9]*' | cut -d= -f2" 2>/dev/null || true)
[ -n "$remember" ] && [ "$remember" -ge 24 ] 2>/dev/null \
  && P "password history enforced (pam_pwhistory remember=$remember)" \
  || W "old passwords can be reused (remember=${remember:-unset})" "enable pam_pwhistory with remember=24 (pw_history role)"
# Measured both ways: without enforce_for_root a reuse performed by root —
# chpasswd included — prints the warning and goes through anyway.
on_node bash -c "grep -v '^#' /etc/pam.d/common-password | grep pam_pwhistory | grep -q enforce_for_root" 2>/dev/null \
  && P "history binds root too (enforce_for_root — chpasswd resets included)" \
  || W "root bypasses the history check" "add enforce_for_root to pam_pwhistory (pw_history role)"
on_node stat -c '%a %U %G' /etc/security/opasswd 2>/dev/null | grep -q '^600 root root$' \
  && P "opasswd is root:root 0600 (it stores password hashes)" \
  || W "opasswd is loose or missing" "install root:root 0600 /etc/security/opasswd (pw_history role)"

echo "-- Filesystem protections (CIS 1.5.x) ------------------------"
for kv in protected_symlinks:1 protected_hardlinks:1 protected_fifos:1 protected_regular:2; do
  key="fs.${kv%:*}"; want="${kv#*:}"
  got=$(sctl "$key")
  if [ "$got" = "$want" ]; then
    P "$key = $got"
  elif [ -z "$got" ]; then
    W "$key is unreadable on this kernel" "expected $want (fs_protected role)"
  else
    W "$key is $got, not $want" "run the fs_protected role"
  fi
done

echo "-- Accounts & files -----------------------------------------"
on_node getent group sudo | grep -qE ':.*[a-z]' \
  && P "A non-root sudo account exists ($(on_node getent group sudo | sed 's/.*://'))" \
  || W "No non-root sudo account found" "create an admin user (admin_user role)"
empty=$(on_node awk -F: '($2==""){print $1}' /etc/shadow | tr '\n' ' ')
[ -z "$empty" ] \
  && P "No accounts with an empty password" \
  || F "Accounts with empty password: $empty" "lock or set passwords (account_hygiene role)"
# Legacy NIS compat entries: inert under nsswitch `files`, but a service
# flipped to `compat` would splice the NIS map in — uid 0 included.
if on_node grep -qE '^[+-]' /etc/passwd /etc/shadow /etc/group; then
  F "NIS compat ('+'/'-') entries present in the account database" "remove them (account_hygiene role)"
else
  P "No NIS compat ('+'/'-') entries in passwd/shadow/group"
fi
# A hash in world-readable /etc/passwd both authenticates and hands every
# local account an offline cracking target.
unshadowed=$(on_node awk -F: '($2!="x"){print $1}' /etc/passwd | tr '\n' ' ')
[ -z "${unshadowed// /}" ] \
  && P "Every /etc/passwd password field is shadowed ('x')" \
  || F "Password material in world-readable /etc/passwd: $unshadowed" "run the account_hygiene role (pwconv)"
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
