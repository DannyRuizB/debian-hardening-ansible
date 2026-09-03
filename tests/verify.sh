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

# With LogLevel VERBOSE (ssh_policies) every deliberately-failed probe below
# (root login, the pre-auth banner check) is worth SEVERAL journal lines to
# fail2ban — enough to land a mid-run ban long before the final section
# tests banning on purpose. Shield this client while the functional checks
# run; the shield is lifted right before the ban test. ignoreip means the
# probes are never counted, so that test still starts from zero.
docker exec dh-test-node fail2ban-client set sshd addignoreip 172.17.0.1 >/dev/null 2>&1 || true

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

echo "== Mount options (/dev/shm) =="
# The mount module writes the options field in its own order — check each
# flag on the fstab line rather than assuming nodev,nosuid,noexec verbatim.
for flag in nodev nosuid noexec; do
  expect_line "fstab pins /dev/shm with $flag" "$flag" \
    grep -E "'^[^#].*[[:space:]]/dev/shm[[:space:]]'" /etc/fstab
done
expect_line "/dev/shm is live-mounted nodev" ",nodev,|,nodev$|^nodev," findmnt -no OPTIONS /dev/shm
expect_line "/dev/shm is live-mounted nosuid" ",nosuid,|,nosuid$|^nosuid," findmnt -no OPTIONS /dev/shm
expect_line "/dev/shm is live-mounted noexec" ",noexec,|,noexec$|^noexec," findmnt -no OPTIONS /dev/shm
# Functional, not just the mount table: drop a real binary into /dev/shm and
# try to run it — the kernel must refuse (Permission denied), exactly what a
# dropper staging its payload there would hit.
on_node cp /bin/true /dev/shm/dha-probe 2>/dev/null || true
if on_node /dev/shm/dha-probe >/dev/null 2>&1; then
  fail "a binary staged in /dev/shm cannot execute (noexec enforced)"
else
  pass "a binary staged in /dev/shm cannot execute (noexec enforced)"
fi
on_node rm -f /dev/shm/dha-probe 2>/dev/null || true

echo "== Warning banners (CIS 1.7) =="
expect_line "sshd effective config: banner /etc/issue.net" \
  "^banner /etc/issue.net$" sudo sshd -T
expect_line "/etc/issue.net carries the legal notice" \
  "Authorized access only" cat /etc/issue.net
expect_line "/etc/issue carries the legal notice" \
  "Authorized access only" cat /etc/issue
# The point of the CIS control: no OS/kernel reconnaissance before login.
if on_node grep -Eq '(\\\\[mrsv]|Debian|Ubuntu)' /etc/issue /etc/issue.net /etc/motd 2>/dev/null; then
  fail "banner files leak no OS/kernel info (no \\m \\r \\s \\v escapes, no distro name)"
else
  pass "banner files leak no OS/kernel info (no \\m \\r \\s \\v escapes, no distro name)"
fi
# Functional, from the outside: sshd must show the banner BEFORE
# authentication — an unauthenticated (failing) connection still sees it.
# Captured first: the ssh is EXPECTED to fail (auth denied), and under
# pipefail its non-zero status would mask a successful grep.
banner_out=$(ssh "${OPTS[@]}" -o ConnectTimeout=3 nobody-here@127.0.0.1 true 2>&1 || true)
if echo "$banner_out" | grep -q "Authorized access only"; then
  pass "the banner reaches an unauthenticated client pre-auth"
else
  fail "the banner reaches an unauthenticated client pre-auth"
fi

echo "== Sudo hardening (CIS 5.3) =="
expect_line "sudoers drop-in sets use_pty" "^Defaults use_pty$" \
  sudo cat /etc/sudoers.d/99-hardening-sudo
expect_line "sudoers drop-in sets a dedicated logfile" \
  '^Defaults logfile="/var/log/sudo.log"$' \
  sudo cat /etc/sudoers.d/99-hardening-sudo
# Functional: with use_pty, sudo runs the command in a NEW pseudo-terminal
# that proxies the caller's — so from a forced-tty session (-tt), `tty`
# outside and inside sudo must report DIFFERENT /dev/pts/N. Without
# use_pty they'd be the same one. (With no tty at all sudo allocates
# nothing — there is nothing to proxy — hence the forced -tt here.)
ptys=$(ssh "${OPTS[@]}" -tt -i "$KEY" opsadmin@127.0.0.1 'tty && sudo -n tty' 2>/dev/null | tr -d '\r')
pty_outer=$(echo "$ptys" | sed -n 1p)
pty_inner=$(echo "$ptys" | sed -n 2p)
if echo "$pty_inner" | grep -q "^/dev/pts/" && [ "$pty_inner" != "$pty_outer" ]; then
  pass "sudo really allocates its own pty for commands (use_pty live: $pty_outer -> $pty_inner)"
else
  fail "sudo really allocates its own pty for commands (use_pty live: got '$pty_outer' -> '$pty_inner')"
fi
# Functional: the command above must land in the dedicated log.
expect_line "sudo activity lands in /var/log/sudo.log" \
  "COMMAND=.*tty" sudo cat /var/log/sudo.log

echo "== SSH session policies (CIS 5.2) =="
expect_line "sshd effective config: allowtcpforwarding no" \
  "^allowtcpforwarding no$" sudo sshd -T
expect_line "sshd effective config: allowagentforwarding no" \
  "^allowagentforwarding no$" sudo sshd -T
expect_line "sshd effective config: maxsessions 4" \
  "^maxsessions 4$" sudo sshd -T
expect_line "sshd effective config: loglevel VERBOSE" \
  "^loglevel VERBOSE$" sudo sshd -T
expect_line "sshd effective config: permituserenvironment no" \
  "^permituserenvironment no$" sudo sshd -T
# Functional: a direct-tcpip channel (ssh -W, same mechanism as -L tunnels)
# must be refused by the server — "administratively prohibited". The login
# itself still works (checked at the top), only the pivoting is gone.
tunnel_out=$(ssh "${OPTS[@]}" -i "$KEY" -W 127.0.0.1:22 opsadmin@127.0.0.1 </dev/null 2>&1 || true)
if echo "$tunnel_out" | grep -qi "administratively prohibited"; then
  pass "a forwarding channel really gets refused (administratively prohibited)"
else
  fail "a forwarding channel really gets refused (got: $(echo "$tunnel_out" | head -1))"
fi
# Functional: the accepted key's fingerprint must be in the auth log —
# the line every forensics pass greps for first (the node logs to journald;
# fail2ban reads it from there). TRAP: expect_line pipes into `grep -q`,
# which exits on the first match — under `pipefail` a big remote output
# (the whole journal) dies of SIGPIPE and the check "fails" despite the
# match. Filter remotely, return a few lines, and force rc 0.
expect_line "auth log records the key fingerprint of our login" \
  "Accepted publickey.*SHA256:" \
  sudo sh -c '"journalctl -u ssh --no-pager 2>/dev/null | grep \"Accepted publickey\" | tail -3 || true"'

echo "== Core dump limits (CIS 1.5) =="
# The limit must arrive through PAM at login — ask a REAL SSH session for its
# ulimit, not the file we wrote. (ssh hands the command to the login shell,
# so ulimit runs as a builtin in a PAM-opened session.)
expect_line "a fresh SSH session has hard core limit 0" '^0$' ulimit -Hc
# hard, not soft: the session must be unable to raise it back.
if on_node 'ulimit -c 1024' >/dev/null 2>&1; then
  fail "the hard core limit cannot be raised back up"
else
  pass "the hard core limit cannot be raised back up"
fi
# root does not match '*' in limits.conf — its own line must cover it.
expect_line "root's sessions have hard core limit 0 too" '^0$' sudo -i ulimit -Hc

echo "== Default umask & shell timeout (CIS 5.4) =="
# A login shell must pick up the 027 default (profile.d and/or pam_umask).
expect_line "a login shell defaults to umask 027" '^0?027$' bash -lc umask
# The proof by consequence: a file created in that session is not
# world-readable (640, not 644).
expect_line "a file created in a login session is not world-readable" \
  '^640$' bash -lc '"rm -f /tmp/umask_probe && touch /tmp/umask_probe && stat -c %a /tmp/umask_probe"'
# TMOUT arrives in login shells and is readonly: assigning to it must fail.
# TRAP: the remote outer shell (non-login) expands $TMOUT BEFORE the inner
# `bash -l` runs — escape the dollar so the login shell does the expansion.
expect_line "login shells carry TMOUT=900" '^900$' bash -lc '"echo \$TMOUT"'
if on_node bash -lc '"TMOUT=5"' >/dev/null 2>&1; then
  fail "TMOUT is readonly (a session cannot raise or unset it)"
else
  pass "TMOUT is readonly (a session cannot raise or unset it)"
fi

echo "== Cron restrictions (CIS 5.1) =="
expect_line "/etc/crontab is 600 root:root" '^600 root root$' \
  sudo stat -c "'%a %U %G'" /etc/crontab
# All five drop-in dirs at once: uniform perms collapse to a single line.
expect_line "the cron.* drop-in dirs are all 700 root:root" '^700 root root$' \
  sudo bash -c '"stat -c \"%a %U %G\" /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d | sort -u | paste -sd:"'
expect_line "cron.allow exists and is 640 root:root" '^640 root root$' \
  sudo stat -c "'%a %U %G'" /etc/cron.allow
if on_node sudo test -e /etc/cron.deny >/dev/null 2>&1; then
  fail "cron.deny is gone (allow-list model, not deny-list)"
else
  pass "cron.deny is gone (allow-list model, not deny-list)"
fi
# The allow-list gates crontab(1). rc alone is ambiguous — an ALLOWED user
# with no crontab also exits 1 ("no crontab for ...") — so read the message.
deny_out=$(on_node crontab -l 2>&1 || true)
if printf '%s\n' "$deny_out" | grep -qi "not allowed"; then
  pass "an unprivileged user cannot use crontab (not on the allow-list)"
else
  fail "an unprivileged user cannot use crontab (not on the allow-list)"
fi
root_out=$(on_node sudo crontab -l 2>&1 || true)
if printf '%s\n' "$root_out" | grep -qi "not allowed"; then
  fail "root is still allowed to use crontab"
else
  pass "root is still allowed to use crontab"
fi

echo "== Password policy (CIS 5.3/5.4) =="
expect_line "pwquality demands at least 14 characters" '^minlen = 14$' \
  grep "'^minlen'" /etc/security/pwquality.conf
expect_line "the policy binds root too (enforce_for_root)" '^enforce_for_root$' \
  grep "'^enforce_for_root'" /etc/security/pwquality.conf
expect_line "pam_pwquality is wired into common-password" 'pam_pwquality\.so' \
  grep pam_pwquality /etc/pam.d/common-password
# Behavioral, through the same library PAM consults (pwscore ships in the
# test image): a weak password must be rejected with the policy's reason...
weak_out=$(on_node bash -c '"echo changeme1 | pwscore"' 2>&1 || true)
if printf '%s\n' "$weak_out" | grep -qiE 'shorter|characters|dictionary'; then
  pass "a weak password is rejected by the quality library"
else
  fail "a weak password is rejected by the quality library (got: $(echo "$weak_out" | head -1))"
fi
# ...and a strong one (14+, all four classes) must score.
expect_ok "a strong password clears the policy" \
  bash -c '"echo Vk9#mQz2.pLw7#xTe | pwscore"'
# The stored hash: set a password on a throwaway account and read the crypt
# prefix — $y$ is yescrypt, whichever path (PAM or login.defs) produced it.
on_node sudo useradd probe-hash 2>/dev/null || true
on_node sudo bash -c '"echo probe-hash:Vk9#mQz2.pLw7#xTe | chpasswd"' >/dev/null 2>&1 || true
expect_line "a freshly set password is stored as yescrypt" '^\$y\$' \
  sudo bash -c "'getent shadow probe-hash | cut -d: -f2'"
on_node sudo userdel probe-hash 2>/dev/null || true
expect_line "login.defs pins ENCRYPT_METHOD to yescrypt" \
  '^ENCRYPT_METHOD[[:space:]]+YESCRYPT$' grep -E "'^ENCRYPT_METHOD'" /etc/login.defs

echo "== File integrity (AIDE, CIS 1.4) =="
expect_ok "the AIDE config exists" sudo test -f /etc/aide/hardening.conf
expect_ok "the AIDE baseline DB was built" sudo test -s /var/lib/aide/hardening.db
expect_line "the config fingerprints /etc" '^/etc' \
  sudo grep "'^/etc'" /etc/aide/hardening.conf
expect_line "a daily check timer is enabled" '^enabled$' \
  sudo systemctl is-enabled aide-check.timer
# Behavioral, the whole point: drop a NEW file into a watched path (/etc)
# and AIDE must report it as added on the next check. The baseline was
# built during hardening without this file, so it is unambiguous drift.
on_node "sudo sh -c 'echo pwn > /etc/aide-probe.conf'" >/dev/null 2>&1 || true
aide_out=$(on_node "sudo aide --config=/etc/aide/hardening.conf --check 2>&1 || true")
# Match with a `case` glob, NOT `printf "$aide_out" | grep -q`: an AIDE
# report listing every added file (this suite keeps adding drop-ins under
# /etc, so the baseline-vs-now diff grows) can run to many lines, and under
# `pipefail` grep -q closing the pipe on its first match kills printf with
# SIGPIPE — the pipeline then "fails" despite the match. A pure-bash case
# has no pipe to break.
case "$aide_out" in
  *aide-probe.conf*) pass "a new file under /etc is caught by an AIDE check (tamper-evident)" ;;
  *)                 fail "a new file under /etc is caught by an AIDE check (tamper-evident)" ;;
esac
on_node "sudo rm -f /etc/aide-probe.conf" >/dev/null 2>&1 || true

echo "== Rootkit detection (rkhunter) =="
expect_ok "rkhunter is installed" sudo test -x /usr/bin/rkhunter
expect_ok "the rkhunter property baseline was taken" sudo test -s /var/lib/rkhunter/db/rkhunter.dat
expect_line "the daily cron job is disabled (we use a timer)" '^CRON_DAILY_RUN="false"$' \
  sudo grep '^CRON_DAILY_RUN=' /etc/default/rkhunter
expect_line "a daily check timer is enabled" '^enabled$' \
  sudo systemctl is-enabled rkhunter-check.timer
# Behavioral: a full check runs and reports. rkhunter exits non-zero on
# warnings (normal on a minimal container), so assert on the output, not rc.
rk_out=$(on_node "sudo rkhunter --check --skip-keypress --report-warnings-only --nocolors 2>&1 || true")
if printf '%s\n' "$rk_out" | grep -qiE "System checks summary|rootkit checks|Warning:"; then
  pass "an rkhunter check runs to completion and reports"
else
  fail "an rkhunter check runs to completion and reports"
fi

echo "== Kernel module blacklist =="
expect_ok "the modprobe blacklist drop-in exists" \
  sudo test -f /etc/modprobe.d/99-hardening-blacklist.conf
# Behavioral, container-safe: `modprobe -n -v` (dry run) consults the config
# without needing module-loading rights or /lib/modules for this kernel. With
# the install directive in place it prints `install /bin/false` and exits 0;
# without it, it FAILS (module unresolvable) — so this check genuinely flips
# from red to green when the role runs.
expect_line "an explicit dccp load is defeated (install /bin/false)" \
  'install /bin/false' sudo modprobe -n -v dccp
expect_line "an explicit cramfs mount helper is defeated too" \
  'install /bin/false' sudo modprobe -n -v cramfs
# The alias door: `blacklist` is what stops auto-loading; assert it is
# declared for every module the role promises, not just the install line.
expect_ok "every blacklisted module has its blacklist line (10/10)" \
  "test \"\$(grep -c '^blacklist ' /etc/modprobe.d/99-hardening-blacklist.conf)\" -eq 10"

echo "== Account lockout (pam_faillock) =="
expect_line "faillock.conf sets deny = 5" '^deny[[:space:]]*=[[:space:]]*5$' \
  sudo grep '^deny' /etc/security/faillock.conf
expect_line "faillock.conf sets a 15-minute unlock_time" '^unlock_time[[:space:]]*=[[:space:]]*900$' \
  sudo grep '^unlock_time' /etc/security/faillock.conf
expect_line "the preauth gate is wired into common-auth" 'pam_faillock\.so preauth' \
  sudo grep pam_faillock /etc/pam.d/common-auth
expect_line "the authfail tally is wired into common-auth" 'pam_faillock\.so authfail' \
  sudo grep pam_faillock /etc/pam.d/common-auth
# Behavioral: create a throwaway password account and drive the REAL PAM
# `login` stack with pamtester(1). Two traps shape this harness:
#  - su(1) is useless under sudo: pam_rootok waves root through without
#    running the auth stack, so nothing ever tallies.
#  - piping a password into su via script(1) never arrives: PAM flushes
#    pending tty input (TCSAFLUSH) before reading. pamtester reads the
#    password from stdin — no pty involved.
# The baseline attempt proves the password actually reaches PAM, so a lock
# "success" can't hide a broken harness. faillock records live under
# /run/faillock and SURVIVE userdel — reset right after creating the account
# or a verify re-run starts already locked. These attempts never touch sshd,
# so they don't feed Fail2Ban (its section runs last, on purpose).
on_node "sudo userdel -r faillock-probe 2>/dev/null; sudo useradd -m faillock-probe && echo 'faillock-probe:C0rrectHorse!x9' | sudo chpasswd && sudo faillock --user faillock-probe --reset" >/dev/null 2>&1 || true
probe_auth() {  # one real authentication attempt with the given password
  on_node "printf '%s\n' '$1' | sudo pamtester login faillock-probe authenticate"
}
if probe_auth 'C0rrectHorse!x9' >/dev/null 2>&1; then
  pass "baseline: the probe account's correct password authenticates"
else
  fail "baseline: the probe account's correct password authenticates"
fi
for _ in 1 2 3 4 5; do probe_auth 'wrongpass' >/dev/null 2>&1 || true; done
if on_node "sudo faillock --user faillock-probe | grep -cE '^20[0-9][0-9]-'" 2>/dev/null | grep -qE '^[5-9]|^[0-9]{2,}'; then
  pass "five failed logins are tallied in faillock"
else
  fail "five failed logins are tallied in faillock"
fi
# The right password must be refused while locked (the whole point).
if probe_auth 'C0rrectHorse!x9' >/dev/null 2>&1; then
  fail "a locked account rejects even the correct password"
else
  pass "a locked account rejects even the correct password"
fi
# A reset frees it: the correct password works again.
on_node "sudo faillock --user faillock-probe --reset" >/dev/null 2>&1 || true
if probe_auth 'C0rrectHorse!x9' >/dev/null 2>&1; then
  pass "faillock --reset unlocks the account"
else
  fail "faillock --reset unlocks the account"
fi
on_node "sudo userdel -r faillock-probe" >/dev/null 2>&1 || true

echo "== File permissions (CIS 6.1) =="
expect_line "/etc/passwd is 644 root:root" '^644 root root$' \
  "stat -c '%a %U %G' /etc/passwd"
expect_line "/etc/shadow is 640 root:shadow" '^640 root shadow$' \
  "sudo stat -c '%a %U %G' /etc/shadow"
expect_line "/etc/gshadow is 640 root:shadow" '^640 root shadow$' \
  "sudo stat -c '%a %U %G' /etc/gshadow"
expect_line "the shadow BACKUP (/etc/shadow-) got the same treatment" '^640 root shadow$' \
  "sudo stat -c '%a %U %G' /etc/shadow-"
# The CI plants a world-writable file, an orphan (UID 12345) and a 777 dir
# BEFORE the first pass — so these three sweeps genuinely flip from red to
# green when the role runs, instead of asserting a vacuum.
expect_ok "no world-writable files outside the scratch dirs" \
  "test -z \"\$(sudo find / -xdev \\( -path /tmp -o -path /var/tmp \\) -prune -o -type f -perm -0002 -print 2>/dev/null)\""
expect_ok "no unowned or ungrouped files" \
  "test -z \"\$(sudo find / -xdev \\( -path /tmp -o -path /var/tmp \\) -prune -o \\( -nouser -o -nogroup \\) -print 2>/dev/null)\""
expect_ok "every world-writable directory carries the sticky bit" \
  "test -z \"\$(sudo find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null)\""

echo "== SSH access control (AllowGroups) =="
expect_line "sshd effective config limits AllowGroups to ssh-users" \
  "^allowgroups ssh-users$" sudo sshd -T
expect_line "the admin user is a member of ssh-users" '(^| )ssh-users( |$)' \
  id -nG opsadmin
# Behavioral: a user with a VALID key but NOT in ssh-users must be refused by
# sshd before auth. We own both ends: make the probe on the node, hand it the
# CI key, and try to log in as it. Then add it to ssh-users, reload, and prove
# it gets in with the SAME key — so the gate is group membership, not the
# credential. Runs inside the fail2ban shield (refusals would feed the jail).
on_node "sudo userdel -r sshprobe 2>/dev/null; sudo useradd -m -s /bin/bash sshprobe && sudo install -d -m 700 -o sshprobe -g sshprobe /home/sshprobe/.ssh && sudo cp /home/opsadmin/.ssh/authorized_keys /home/sshprobe/.ssh/authorized_keys && sudo chown sshprobe:sshprobe /home/sshprobe/.ssh/authorized_keys" >/dev/null 2>&1 || true
if ssh "${OPTS[@]}" -i "$KEY" sshprobe@127.0.0.1 true >/dev/null 2>&1; then
  fail "a keyed user outside ssh-users is refused by AllowGroups"
else
  pass "a keyed user outside ssh-users is refused by AllowGroups"
fi
on_node "sudo usermod -aG ssh-users sshprobe && sudo systemctl reload ssh" >/dev/null 2>&1 || true
if ssh "${OPTS[@]}" -i "$KEY" sshprobe@127.0.0.1 true >/dev/null 2>&1; then
  pass "adding the user to ssh-users lets the same key in"
else
  fail "adding the user to ssh-users lets the same key in"
fi
on_node "sudo userdel -r sshprobe 2>/dev/null; sudo systemctl reload ssh" >/dev/null 2>&1 || true

echo "== Service sandboxing (systemd) =="
# Ask systemd for the EFFECTIVE properties of the running fail2ban unit — the
# drop-in is only real if the manager actually applied it.
expect_line "fail2ban runs with NoNewPrivileges" "^NoNewPrivileges=yes$" \
  sudo systemctl show fail2ban -p NoNewPrivileges
expect_line "fail2ban has a private /tmp" "^PrivateTmp=yes$" \
  sudo systemctl show fail2ban -p PrivateTmp
expect_line "fail2ban has ProtectSystem=full" "^ProtectSystem=full$" \
  sudo systemctl show fail2ban -p ProtectSystem
expect_line "fail2ban has ProtectHome" "^ProtectHome=yes$" \
  sudo systemctl show fail2ban -p ProtectHome
# Sandboxed AND still working — if the confinement had broken it the unit
# wouldn't be active, and the ban test below would fail anyway.
expect_line "fail2ban is still active under the sandbox" "^active$" \
  sudo systemctl is-active fail2ban

echo "== Journald persistence (CIS 4.2.2) =="
# `systemd-analyze cat-config` prints the EFFECTIVE merged config (base file +
# our drop-in), so this checks what journald actually uses, not just the file.
expect_line "journald storage is persistent (effective)" "^Storage=persistent$" \
  "sudo systemd-analyze cat-config systemd/journald.conf | grep -E '^Storage='"
expect_line "journald compresses stored logs (effective)" "^Compress=yes$" \
  "sudo systemd-analyze cat-config systemd/journald.conf | grep -E '^Compress='"
expect_line "journald caps its disk footprint (effective)" "^SystemMaxUse=" \
  "sudo systemd-analyze cat-config systemd/journald.conf | grep -E '^SystemMaxUse='"
# Behavioral: persistent storage means the on-disk journal directory exists
# (journald creates it under /var/log/journal instead of the volatile /run
# tmpfs the default uses).
expect_ok "the persistent journal directory exists on disk" \
  sudo test -d /var/log/journal

echo "== Su restriction (CIS 5.7) =="
expect_ok "the sugroup group exists" sudo getent group sugroup
expect_line "pam.d/su gates su on sugroup membership by real uid" \
  'pam_wheel\.so use_uid group=sugroup' \
  "sudo grep -E '^auth[[:space:]]+required[[:space:]]+pam_wheel' /etc/pam.d/su"
# CIS wants the group EMPTY: sudo is the sanctioned path, so every member is a
# deliberate, auditable exception.
expect_line "the sugroup group is empty (sudo is the sanctioned path)" '^$' \
  "sudo getent group sugroup | cut -d: -f4"
# Behavioral, mirroring the ssh_access role's proof: the SAME user with the
# SAME *correct* root password is refused outside the group and gets in inside
# it — the door is the membership, not the credential. Four traps shaped this:
#  - Neither the exit code nor su's message discriminates: with the faillock
#    role in place, a failed password also reports "Permission denied", the
#    very string pam_wheel produces. The journal doesn't either — with no
#    password delivered both cases log the same pam_unix failure. The only
#    honest signal is whether the shell actually opens.
#  - So the password must really arrive, and a pipe never does (PAM flushes
#    queued tty input, TCSAFLUSH). expect(1) drives a real pty and types
#    AFTER the prompt — that is why the faillock probe needed pamtester and
#    this one needs expect.
#  - Never run it as root: pam_wheel waves uid 0 straight through, just as
#    pam_rootok defeats the faillock probe.
#  - Both probe passwords must satisfy the password_policy role (>= 14 chars,
#    4 classes, username not contained — "Root" inside a root password is
#    refused) or chpasswd quietly leaves the account with no password.
# root's locked hash is saved, restored right after, and re-asserted.
SU_PASS='Qx7!vTz9#mLp2Wb'
on_node "sudo userdel -r suprobe 2>/dev/null; sudo useradd -m suprobe && echo 'suprobe:Verify!Su9Probe#2026' | sudo chpasswd && sudo faillock --user suprobe --reset" >/dev/null 2>&1 || true
root_hash=$(on_node "sudo getent shadow root | cut -d: -f2")
on_node "echo 'root:$SU_PASS' | sudo chpasswd" >/dev/null 2>&1 || true
# Heredoc over ssh stdin: no quoting maze, and the password stays in one place.
on_node "sudo tee /tmp/su-probe.exp >/dev/null && sudo chmod 644 /tmp/su-probe.exp" <<EXP >/dev/null 2>&1
set timeout 15
spawn su - root -c id
expect {
  "Password:" { send "$SU_PASS\r"; exp_continue }
  "uid=0" { puts "RESULT: IN"; exit 0 }
  "Permission denied" { puts "RESULT: DENIED"; exit 1 }
  "Authentication failure" { puts "RESULT: AUTHFAIL"; exit 2 }
  timeout { puts "RESULT: TIMEOUT"; exit 3 }
}
EXP
# Run the probe through `docker exec` (like the fail2ban shield above) rather
# than over SSH: this repo's admin_user role grants `opsadmin ALL=NOPASSWD:
# ALL`, whose implicit Runas is root only, so `sudo -u suprobe …` falls through
# to `%sudo ALL=(ALL:ALL) ALL` and asks for a password. (The Bash twin's
# sudoers line allows any target user, so there it runs over SSH.) Either way
# the uid that matters is the real uid of the su process — suprobe.
#
# PIPEFAIL TRAP (the ssh_policies one in a new disguise): the refusal under
# test makes expect exit 1, and `su_try | grep -q` would report the pipeline as
# failed even though grep matched. Capture, then match.
su_try() { docker exec dh-test-node sudo -u suprobe expect -f /tmp/su-probe.exp 2>&1 || true; }
out=$(su_try)
case "$out" in
  *"RESULT: DENIED"*) pass "a user outside sugroup is refused su even with the correct root password" ;;
  *) fail "a user outside sugroup is refused su even with the correct root password" ;;
esac
on_node "sudo usermod -aG sugroup suprobe && sudo faillock --user suprobe --reset" >/dev/null 2>&1 || true
out=$(su_try)
case "$out" in
  *"RESULT: IN"*) pass "the same user inside sugroup gets a root shell with the same password" ;;
  *) fail "the same user inside sugroup gets a root shell with the same password" ;;
esac
on_node "sudo usermod -p '$root_hash' root; sudo gpasswd -d suprobe sugroup; sudo userdel -r suprobe; sudo rm -f /tmp/su-probe.exp" >/dev/null 2>&1 || true
expect_line "root's password is locked again after the probe" '^[!*]' \
  sudo bash -c "'getent shadow root | cut -d: -f2'"
# Anti-lockout: root must keep its own su (pam_rootok is above pam_wheel).
expect_ok "root can still su despite the restriction" sudo su - root -c true

echo "== System accounts (CIS 5.4.2 / 6.2.9) =="
# The CI plants `dhsvc` BEFORE any pass with /bin/bash and a real password —
# a packaged-daemon leftover, and a valid su / SSH target. Both gates must
# have been taken away by the role.
expect_line "the planted service account now has a non-login shell" \
  '(/usr/sbin/nologin|/bin/false)$' \
  "sudo getent passwd dhsvc"
expect_line "the planted service account's password is locked" '^dhsvc L ' \
  "sudo passwd -S dhsvc"
# Behavioral, and it needs NO password: root walks past pam_rootok, so `su -`
# gets all the way to exec'ing the account's shell — and nologin is what
# refuses. A shell that opened would print the uid instead. This is the honest
# signal (same reasoning as the su_restriction probe above: never trust an
# exit code several mechanisms share).
sysacct_out=$(on_node "sudo su - dhsvc -c id 2>&1" || true)
case "$sysacct_out" in
  *"not available"*|*"This account is currently"*)
    pass "nobody can get an interactive shell as the service account (nologin refuses even root's su)" ;;
  *uid=*)
    fail "nobody can get an interactive shell as the service account (nologin refuses even root's su)" ;;
  *)
    fail "nobody can get an interactive shell as the service account (unexpected: $sysacct_out)" ;;
esac
# The role must not have swallowed the humans or the recovery paths.
expect_line "the admin user keeps its login shell (humans untouched)" '(/bin/bash|/bin/sh)$' \
  "sudo getent passwd opsadmin"
expect_ok "the admin user can still run a login shell" sudo su - opsadmin -c true
# root: locking it would brick single-user recovery, and CIS carves out the
# sync/shutdown/halt trio whose entire purpose is a login shell.
expect_line "root keeps a real shell (single-user recovery survives)" '(/bin/bash|/bin/sh)$' \
  "sudo getent passwd root"
expect_line "the sync account keeps its namesake shell (CIS exception)" '/bin/sync$' \
  "sudo getent passwd sync"

echo "== Log file permissions (CIS 4.2.3) =="
# The CI plants /var/log/dh-app.log at 0666 BEFORE any pass; the sweep must
# have stripped group-write and all world access (666 -> 640), not by vacuum.
expect_line "the planted world-readable log is now 0640" '^640$' \
  "sudo stat -c %a /var/log/dh-app.log"
# The deliberate exceptions survive: who/last for everyone needs wtmp 664,
# while btmp stays tighter (failed logins record passwords typed as users).
expect_line "wtmp keeps its by-design 664 root:utmp" '^664 root utmp$' \
  "sudo stat -c '%a %U %G' /var/log/wtmp"
expect_line "btmp is 660 root:utmp (tighter: it sees typed secrets)" '^660 root utmp$' \
  "sudo stat -c '%a %U %G' /var/log/btmp"
# Sweep-wide: nothing under /var/log is group-writable or world-accessible
# beyond the utmp family — the promise, not just the planted file.
leaky=$(on_node "sudo find /var/log -xdev -type f ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' -perm /0037" 2>/dev/null || true)
if [ -z "$leaky" ]; then
  pass "no log file is world-accessible or group-writable (utmp family aside)"
else
  fail "no log file is world-accessible or group-writable (leaky: $leaky)"
fi
# rsyslog: the drop-in is in place and the daemon accepts the full config.
expect_line "rsyslog drop-in pins FileCreateMode 0640" 'FileCreateMode 0640' \
  "sudo cat /etc/rsyslog.d/99-hardening.conf"
expect_ok "rsyslog still validates its config (rsyslogd -N1)" sudo rsyslogd -N1
# Behavioral, against the planted drift: the CI set rsyslog.conf's own
# FileCreateMode to 0644 before the play. Delete syslog, restart, log one
# line — the file rsyslog creates FROM SCRATCH must be born 0640 because the
# drop-in (loaded after the main file) wins over the drifted value.
on_node "sudo rm -f /var/log/syslog && sudo systemctl restart rsyslog" >/dev/null 2>&1 || true
on_node "logger -t dh-verify 'log-permissions probe'" >/dev/null 2>&1 || true
newmode=""
for _ in $(seq 1 10); do
  newmode=$(on_node "sudo stat -c %a /var/log/syslog 2>/dev/null" || true)
  [ -n "$newmode" ] && break
  sleep 1
done
if [ "$newmode" = "640" ]; then
  pass "a log file rsyslog creates from scratch is born 0640 (drop-in beats drift)"
else
  fail "a log file rsyslog creates from scratch is born 0640 (got: ${newmode:-missing})"
fi

echo "== Logrotate permissions (CIS 4.4) =="
# Rotation is the THIRD way a log is born: logrotate's create directive
# decides the mode of every file it re-creates, and stock Debian's global
# create is bare (clones the old mode) while dpkg/alternatives say 644.
expect_line "logrotate global create is pinned to 0640" '^create 0640' \
  "sudo cat /etc/logrotate.conf"
# No snippet may re-create a log group-writable/executable or world-anything;
# wtmp/btmp keep their designed utmp split, same exception as the sweep.
loosecreate=$(on_node "grep -RE '^[[:space:]]*create[[:space:]]+0?[0-7]([1-35-7][0-7]|[0-7][1-7])([[:space:]]|\$)' /etc/logrotate.d 2>/dev/null | grep -Ev '^/etc/logrotate.d/(wtmp|btmp):'" || true)
if [ -z "$loosecreate" ]; then
  pass "no logrotate.d snippet re-creates logs beyond owner+group (wtmp/btmp aside)"
else
  fail "no logrotate.d snippet re-creates logs beyond owner+group (loose: $loosecreate)"
fi
expect_ok "logrotate still swallows the whole edited config" \
  sudo logrotate -d /etc/logrotate.conf
# Behavioral: plant a fresh 0600 log with a snippet that says NOTHING about
# create, force a real rotation of the full config, and the re-created file
# must be born 0640 — the pinned GLOBAL mode applied (a bare create would
# have cloned 0600, a drifted one 0644). The stock dpkg snippet — 644 on
# stock Debian, tightened by the role — must re-create dpkg.log 0640 too,
# and the whole of /var/log must come out as tight as the sweep left it:
# rotation no longer rots the sweep.
on_node "printf 'probe\n' | sudo tee /var/log/dh-rotate-probe.log >/dev/null && sudo chmod 0600 /var/log/dh-rotate-probe.log" >/dev/null 2>&1 || true
on_node "printf '/var/log/dh-rotate-probe.log {\n  daily\n  rotate 1\n}\n' | sudo tee /etc/logrotate.d/dh-rotate-probe >/dev/null" >/dev/null 2>&1 || true
on_node "sudo logrotate --force /etc/logrotate.conf" >/dev/null 2>&1 || true
probemode=$(on_node "sudo stat -c %a /var/log/dh-rotate-probe.log 2>/dev/null" || true)
if [ "$probemode" = "640" ]; then
  pass "a log re-created by forced rotation is born 0640 (global create pin holds)"
else
  fail "a log re-created by forced rotation is born 0640 (got: ${probemode:-missing})"
fi
dpkgmode=$(on_node "sudo stat -c %a /var/log/dpkg.log 2>/dev/null" || true)
if [ "$dpkgmode" = "640" ]; then
  pass "dpkg.log survives its own rotation restricted (stock 644 snippet tightened)"
else
  fail "dpkg.log survives its own rotation restricted (got: ${dpkgmode:-missing})"
fi
postleaky=$(on_node "sudo find /var/log -xdev -type f ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' -perm /0037" 2>/dev/null || true)
if [ -z "$postleaky" ]; then
  pass "after a full forced rotation /var/log is still tight (utmp family aside)"
else
  fail "after a full forced rotation /var/log is still tight (leaky: $postleaky)"
fi
# Leave no probe behind.
on_node "sudo rm -f /etc/logrotate.d/dh-rotate-probe /var/log/dh-rotate-probe.log*" >/dev/null 2>&1 || true

echo "== Auditd staged and enabled (CIS 4.1) =="
# The promise is configuration: package on disk, ruleset staged, service
# enabled at boot, history kept. Loading into the running kernel is not
# probed — the audit netlink is not namespaced, so this container gets EPERM
# by construction; on real metal the enabled service loads the rules at boot.
expect_ok "auditd is installed" sudo dpkg -s auditd
expect_line "auditd is enabled at boot" '^enabled$' \
  sudo systemctl is-enabled auditd
expect_ok "the staged ruleset is root-only (0640 root:root)" \
  "test \"\$(sudo stat -c '%a %U %G' /etc/audit/rules.d/hardening.rules)\" = '640 root root'"
# Behavioral, container-safe: run the REAL toolchain. augenrules (without
# --load) compiles every rules.d file into /etc/audit/audit.rules — if our
# staged rules survive that compile and the keys land in the merged output,
# they are exactly what the kernel will be handed at boot.
on_node "sudo augenrules >/dev/null 2>&1" || true
merged=$(on_node "sudo cat /etc/audit/audit.rules 2>/dev/null" || true)
for key in identity scope sshd time-change modules; do
  if printf '%s\n' "$merged" | grep -q -- "-k $key"; then
    pass "augenrules compiles the staged rules: '-k $key' reaches the merged audit.rules"
  else
    fail "augenrules compiles the staged rules: '-k $key' missing from the merged audit.rules"
  fi
done
expect_line "audit history is kept, not rotated away" '^max_log_file_action = keep_logs$' \
  "sudo grep -E '^max_log_file_action' /etc/audit/auditd.conf"

echo "== Home directory permissions (CIS 6.2) =="
# The CI plants dhhome with a 755 home plus a .netrc and a .forward before
# the first pass — these checks flip from red to green because the role did
# real work, not by vacuum.
expect_line "the planted 755 home was tightened to 750" '^750$' \
  "sudo stat -c '%a' /home/dhhome"
expect_ok "the planted .netrc (cleartext credentials) is gone" \
  "sudo test ! -e /home/dhhome/.netrc"
expect_ok "the planted .forward (silent mail redirect) is gone" \
  "sudo test ! -e /home/dhhome/.forward"
expect_line "root's home keeps Debian's 700" '^700$' \
  "sudo stat -c '%a' /root"
# The whole promise, not just the planted case: no interactive home (uid>=1000
# with a real shell, plus root) may keep group-write or any world access.
loosehomes=$(on_node "awk -F: '(\$3 >= 1000 && \$7 !~ /(nologin|false)\$/) || \$1 == \"root\" { print \$6 }' /etc/passwd | while read -r h; do [ -d \"\$h\" ] || continue; m=\$(sudo stat -c '%a' \"\$h\"); [ \$((8#\$m & 8#0027)) -ne 0 ] && echo \"\$h=\$m\"; done; true" 2>/dev/null || true)
if [ -z "$loosehomes" ]; then
  pass "every interactive home is 750 or tighter"
else
  fail "every interactive home is 750 or tighter (loose: $loosehomes)"
fi
# Behavioral: the mode is the lock, not the file's absence. As plain opsadmin
# (no sudo) the tightened home refuses to open; with sudo it still opens —
# proving the denial comes from o-rwx, not from a missing directory.
if on_node "ls /home/dhhome" >/dev/null 2>&1; then
  fail "another local user cannot list the tightened home (o-rwx at work)"
else
  pass "another local user cannot list the tightened home (o-rwx at work)"
fi
expect_ok "…while root still can (the denial is the mode, not absence)" \
  "sudo ls /home/dhhome"

echo "== Process isolation (/proc hidepid + ptrace_scope) =="
# The CI plants the offending state before the first pass: /proc mounted
# WITHOUT hidepid and ptrace_scope back at 0, so these checks flip from red
# to green because the role did the work.
expect_line "/proc is mounted with hidepid (list hidden)" 'hidepid=(2|invisible)' \
  "findmnt -no OPTIONS /proc"
expect_line "the hidepid option is pinned in fstab (survives a reboot)" 'hidepid=' \
  "grep -E '^[^#[:space:]]+[[:space:]]+/proc[[:space:]]' /etc/fstab"
expect_line "kernel.yama.ptrace_scope is 1 (only a parent may attach)" '^1$' \
  "sudo sysctl -n kernel.yama.ptrace_scope"
expect_line "ptrace_scope is pinned in its own drop-in" '^kernel.yama.ptrace_scope = 1$' \
  "grep -E '^kernel.yama.ptrace_scope' /etc/sysctl.d/99-hardening-process.conf"
# THE behavioral check, and the whole point of the role: an unprivileged
# account must see ONLY its own processes. Before hardening, `ps` as nobody
# lists root's init/journald/cron (verified on a stock node) — the free
# inventory that also leaks passwords sitting in other users' command lines.
# 2>/dev/null on the ssh call: the pre-auth banner lands on stderr and would
# otherwise print in the middle of the check list.
others=$(on_node "sudo setpriv --reuid=65534 --regid=65534 --clear-groups ps -eo user= 2>/dev/null | sort -u | grep -v nobody | tr '\n' ' '" 2>/dev/null || true)
if [ -z "$(printf '%s' "$others" | tr -d ' ')" ]; then
  pass "an unprivileged user sees no other user's processes in ps"
else
  fail "an unprivileged user sees no other user's processes in ps (saw: $others)"
fi
# …and root is deliberately exempt: hidepid must not blind the admin.
expect_ok "root still sees the whole process table" \
  "sudo ps -eo user= | sort -u | grep -q '^root$'"

echo "== Guess cost (yescrypt cost factor + fail delay) =="
expect_line "login.defs pins YESCRYPT_COST_FACTOR 11" '^YESCRYPT_COST_FACTOR[[:space:]]+11$' \
  grep -E '^YESCRYPT_COST_FACTOR' /etc/login.defs
expect_line "login.defs pins FAIL_DELAY 5" '^FAIL_DELAY[[:space:]]+5$' \
  grep -E '^FAIL_DELAY' /etc/login.defs
# The wiring must sit on the FAILURE path: after pam_unix but before the
# stack-enders — faillock's authfail dies and the closing pam_deny is
# requisite, so a delay line below either of those never runs (verified on a
# stock node: appended after the deny, the delay simply doesn't happen).
expect_ok "pam_faildelay sits on the failure path (above authfail/deny)" \
  "grep -v '^#' /etc/pam.d/common-auth | awk '/pam_faildelay/{f=NR} /authfail|pam_deny/{if (!d) d=NR} END{exit !(f && d && f<d)}'"
# Behavioral: a password minted NOW must carry yescrypt's maximum cost —
# $y$jFT$ encodes factor 11 where the stock default is $y$j9T$ (factor 5).
# chpasswd, newusers and a PAM password change all read the pin from
# login.defs (verified empirically on the node before writing the role).
on_node "sudo userdel -r cost-probe 2>/dev/null; sudo useradd cost-probe && echo 'cost-probe:Guess#Cost!v8Rt' | sudo chpasswd" >/dev/null 2>&1 || true
expect_line "a hash minted now carries maximum cost (\$y\$jFT\$...)" '^\$y\$jFT\$' \
  "sudo getent shadow cost-probe | cut -d: -f2"
on_node "sudo userdel -r cost-probe" >/dev/null 2>&1 || true
# Behavioral: time a real failed authentication. The probe's hash is planted
# directly (usermod -p, sha-512) because a cost-11 yescrypt verification is
# itself ~1 s in this container and the point is to measure the DELAY, not
# the hash. Timed inside the node so ssh round-trips don't blur the clock.
# sshd's PAM stack has no fail delay of its own (login's does), so without
# the role this same probe fails in ~2.5 s at worst (pam_unix's built-in
# 2 s, randomized); with FAIL_DELAY 5 the wait lands in 3.75-6.25 s.
on_node "sudo userdel -r delay-probe 2>/dev/null; sudo useradd -m delay-probe && sudo usermod -p '\$6\$dhguesscost\$YjwtovdqqeRxYMPeCxTdqEPIuJ/f5QyiFIBqX0.Nc1bYIYgjtBo8/HLVv7jAcPvu.P.UQCa0P81cjX81GiBap0' delay-probe && sudo faillock --user delay-probe --reset" >/dev/null 2>&1 || true
elapsed_fail=$(on_node "start=\$(date +%s%N); printf 'totally-wrong\n' | sudo pamtester sshd delay-probe authenticate >/dev/null 2>&1; end=\$(date +%s%N); echo \$(( (end-start)/1000000 ))" 2>/dev/null || echo 0)
if [ "${elapsed_fail:-0}" -ge 3000 ]; then
  pass "a failed authentication pays the fail delay (${elapsed_fail} ms >= 3000)"
else
  fail "a failed authentication pays the fail delay (took ${elapsed_fail} ms, expected >= 3000)"
fi
# …and the correct password pays neither price: libpam only applies the
# delay when the authentication ultimately fails.
ok_result=$(on_node "start=\$(date +%s%N); printf 'Delay#Probe!x7Qz\n' | sudo pamtester sshd delay-probe authenticate >/dev/null 2>&1 && auth=ok || auth=bad; end=\$(date +%s%N); echo \$auth \$(( (end-start)/1000000 ))" 2>/dev/null || echo "bad 999999")
if [ "$(printf '%s' "$ok_result" | awk '{print $1}')" = ok ] && [ "$(printf '%s' "$ok_result" | awk '{print $2}')" -lt 2500 ]; then
  pass "the correct password authenticates with no delay ($(printf '%s' "$ok_result" | awk '{print $2}') ms)"
else
  fail "the correct password authenticates with no delay (got: $ok_result)"
fi
# faillock records live under /run/faillock and survive userdel — reset first.
on_node "sudo faillock --user delay-probe --reset; sudo userdel -r delay-probe" >/dev/null 2>&1 || true

echo "== Root PATH integrity (CIS 6.2.8) =="
# The CI plants offenders in ALL THREE sources that set root's PATH on Debian,
# so every check below flips from red to green because the role did the work.
#
# `stat -Lc`, not `stat -c`: on any modern Debian /bin and /sbin are SYMLINKS
# into /usr (usrmerge) and a symlink is always mode 777 — the naive check
# reports every stock system as having world-writable PATH directories. This
# is the trap that shaped the whole step.
unsafe_path_entries() {  # prints one line per unsafe entry of the PATH given
  on_node "printf '%s' '$1' | tr ':' '\n' | while IFS= read -r d; do
      [ -z \"\$d\" ] && { echo 'EMPTY'; continue; }
      case \"\$d\" in /*) ;; *) echo \"RELATIVE \$d\"; continue;; esac
      [ -d \"\$d\" ] || { echo \"MISSING \$d\"; continue; }
      m=\$(sudo stat -Lc %a \"\$d\"); case \"\$m\" in *[2367]) echo \"LOOSE \$d \$m\";; esac
    done; true" 2>/dev/null
}

supath=$(on_node "awk '\$1==\"ENV_SUPATH\"{sub(/^[^=]*=/, \"\", \$2); print \$2; exit}' /etc/login.defs" 2>/dev/null || true)
bad=$(unsafe_path_entries "$supath")
if [ -z "$bad" ] && [ -n "$supath" ]; then
  pass "login.defs ENV_SUPATH has no unsafe entries"
else
  fail "login.defs ENV_SUPATH has no unsafe entries (found: $(printf '%s' "$bad" | tr '\n' ' '))"
fi

profile_paths=$(on_node "grep -hoE '^[[:space:]]*PATH=\"[^\"]*\"' /etc/profile | sed 's/.*PATH=\"//; s/\"\$//'" 2>/dev/null || true)
bad=""
while IFS= read -r p; do
  [ -n "$p" ] || continue
  bad="$bad$(unsafe_path_entries "$p")"
done <<< "$profile_paths"
if [ -z "$bad" ] && [ -n "$profile_paths" ]; then
  pass "/etc/profile PATH lines have no unsafe entries (this is the file that WINS)"
else
  fail "/etc/profile PATH lines have no unsafe entries (found: $(printf '%s' "$bad" | tr '\n' ' '))"
fi

cronpath=$(on_node "awk -F= '\$1==\"PATH\"{print \$2; exit}' /etc/crontab" 2>/dev/null || true)
bad=$(unsafe_path_entries "$cronpath")
if [ -z "$bad" ]; then
  pass "/etc/crontab PATH has no unsafe entries (root's scheduled jobs)"
else
  fail "/etc/crontab PATH has no unsafe entries (found: $(printf '%s' "$bad" | tr '\n' ' '))"
fi

# The step treats two kinds of offender differently, and that distinction IS
# the promise: a FIXABLE entry is fixed and KEPT (deleting a directory the
# admin put in the PATH would break every locally installed binary), an
# UNFIXABLE one is dropped. This is also where the Bash twin's own bug was caught:
# sanitizing the lists before tightening the modes deleted /usr/local/bin
# from the PATH instead of fixing it.
expect_line "a loose directory was tightened, not deleted from the PATH" '/opt/dh-path-loose' \
  "grep -hoE '^[[:space:]]*PATH=\"[^\"]*\"' /etc/profile | head -1"
# Asserting the WRITE bits, not a literal mode: the sticky bit these dirs
# carry comes from step 20 (it sets +t on world-writable directories, which
# these were when planted), so the honest end state is 1755, not 755. What
# matters for a PATH hijack is that group and other cannot write.
expect_ok "…and it is no longer writable by anyone but root" \
  "test \$(( 8#\$(sudo stat -Lc %a /opt/dh-path-loose) & 8#0022 )) -eq 0"
expect_ok "the loosened /usr/local/bin also survived, tightened" \
  "test \$(( 8#\$(sudo stat -Lc %a /usr/local/bin) & 8#0022 )) -eq 0"
expect_ok "the entry that could NOT be fixed (a missing directory) is gone" \
  "! grep -q dh-path-gone /etc/login.defs /etc/profile /etc/crontab"

# Behavioral, and the whole point: the PATH a real root login actually gets.
# `sudo -i printenv PATH` asks the login shell itself instead of echoing a
# variable — an unescaped $PATH would be expanded by the OUTER non-login
# shell before ever reaching the login shell (the step-13 trap).
effective=$(on_node "sudo -i printenv PATH" 2>/dev/null || true)
case ":$effective:" in
  *::*|*:.:*|*dh-path-gone*)
    fail "a real root login shell gets a clean PATH (got: $effective)" ;;
  *)
    pass "a real root login shell gets a clean PATH ($effective)" ;;
esac
# And the symlinks were left alone: chmod on /bin would have changed the LINK.
expect_line "/bin is still an untouched symlink (never chmod'ed)" '^lrwxrwxrwx$' \
  "stat -c %A /bin"

echo "== Step 33: apt updater sandboxing (systemd) =="
# Ask systemd for the EFFECTIVE properties of the apt-daily-upgrade unit — a
# drop-in is only real if the manager applied it (a oneshot reports its
# configured sandbox even while inactive).
expect_line "apt updater runs with NoNewPrivileges" "^NoNewPrivileges=yes$" \
  "sudo systemctl show apt-daily-upgrade.service -p NoNewPrivileges"
expect_line "apt updater has a private /tmp" "^PrivateTmp=yes$" \
  "sudo systemctl show apt-daily-upgrade.service -p PrivateTmp"
expect_line "apt updater has ProtectHome" "^ProtectHome=yes$" \
  "sudo systemctl show apt-daily-upgrade.service -p ProtectHome"
# The two flags that MUST stay off, or apt breaks — the lesson of the step,
# asserted so a well-meaning edit that adds them gets caught. ProtectSystem
# would make /usr read-only (dpkg can't install); RestrictSUIDSGID blocks
# installing setuid binaries (measured: passwd reinstall fails with status 100).
expect_line "apt updater does NOT set ProtectSystem (dpkg must write /usr)" "^ProtectSystem=no$" \
  "sudo systemctl show apt-daily-upgrade.service -p ProtectSystem"
expect_line "apt updater does NOT set RestrictSUIDSGID (dpkg installs setuid bins)" "^RestrictSUIDSGID=no$" \
  "sudo systemctl show apt-daily-upgrade.service -p RestrictSUIDSGID"

echo "== Step 34: password history (pam_pwhistory) =="
expect_line "the pwhistory profile pins remember=24 with root enforced" 'pam_pwhistory\.so remember=24 use_authtok enforce_for_root' \
  grep pam_pwhistory /usr/share/pam-configs/hardening-pwhistory
expect_line "pam_pwhistory is wired into common-password" 'pam_pwhistory\.so remember=24' \
  "grep -v '^#' /etc/pam.d/common-password | grep pam_pwhistory"
# Position (the profile's Priority 512 decides it): strength first, history
# second, and only then the module that actually lands the change — a
# history line BELOW pam_unix would be consulted after the fact.
expect_ok "pwhistory sits between pwquality and pam_unix (strength, history, change)" \
  "grep -v '^#' /etc/pam.d/common-password | awk '/pam_pwquality/{q=NR} /pam_pwhistory/{h=NR} /pam_unix/{u=NR} END{exit !(q && h && u && q<h && h<u)}'"
# opasswd stores password HASHES — shadow-grade sensitivity.
expect_line "opasswd exists as root:root 0600 (it holds password hashes)" '^600 root root$' \
  "sudo stat -c '%a %U %G' /etc/security/opasswd"
# Behavioral crown: change, change again, try to come BACK — refused; a
# genuinely new password still lands (the gate refuses reuse, not change).
# All through pamtester chauthtok as root, which is exactly the chpasswd
# path (measured before writing the step: chpasswd traverses this stack).
on_node "sudo userdel -r hist-probe 2>/dev/null; sudo sed -i '/^hist-probe:/d' /etc/security/opasswd; sudo useradd -m hist-probe" >/dev/null 2>&1 || true
expect_ok "a first password change is recorded in the history" \
  "printf 'Xkr9-Vega-Lumbre-71\nXkr9-Vega-Lumbre-71\n' | sudo pamtester passwd hist-probe chauthtok"
expect_ok "a second change moves the account forward" \
  "printf 'Brumal-Cedro-904-Yq\nBrumal-Cedro-904-Yq\n' | sudo pamtester passwd hist-probe chauthtok"
reuse_out=$(on_node "printf 'Xkr9-Vega-Lumbre-71\nXkr9-Vega-Lumbre-71\n' | sudo pamtester passwd hist-probe chauthtok 2>&1" 2>/dev/null; echo "rc=$?")
if printf '%s' "$reuse_out" | grep -q 'rc=0'; then
  fail "coming back to an old password must be refused (the change went through)"
else
  if printf '%s' "$reuse_out" | grep -q 'already been used\|has been already used'; then
    pass "coming back to an old password is refused, and for the right reason"
  else
    fail "reuse was refused but not by pwhistory (got: $(printf '%s' "$reuse_out" | tail -c 120))"
  fi
fi
expect_ok "a genuinely new password is still accepted (the gate refuses reuse, not change)" \
  "printf 'Nogal+Brisa-7714Jt\nNogal+Brisa-7714Jt\n' | sudo pamtester passwd hist-probe chauthtok"
on_node "sudo userdel -r hist-probe 2>/dev/null; sudo sed -i '/^hist-probe:/d' /etc/security/opasswd" >/dev/null 2>&1 || true

echo "== Role 35: SSH crypto policy =="
# Effective negotiation lists straight from sshd — not the file we wrote.
crypto_conf=$(on_node sudo sshd -T 2>/dev/null)
macs_line=$(printf '%s\n' "$crypto_conf" | grep '^macs ')
case "$macs_line" in
  *sha1*|*umac-64*) fail "effective MACs carry no sha1 and no 64-bit umac" ;;
  *etm*)            pass "effective MACs carry no sha1 and no 64-bit umac" ;;
  *)                fail "effective MACs carry no sha1 and no 64-bit umac" ;;
esac
kex_line=$(printf '%s\n' "$crypto_conf" | grep '^kexalgorithms ')
case "$kex_line" in
  *ecdh-sha2-nistp*) fail "effective kex has no NIST P-curves" ;;
  *mlkem768*)        pass "effective kex has no NIST P-curves" ;;
  *)                 fail "effective kex has no NIST P-curves" ;;
esac
case "$crypto_conf" in
  *cbc*) fail "effective ciphers carry no CBC mode" ;;
  *)     pass "effective ciphers carry no CBC mode" ;;
esac

# The behavioural quartet. Options go BEFORE the destination (after it they
# are silently part of the REMOTE command — that mistake produced a fake
# "weak MAC accepted" while this step was being probed in the Bash twin).
# The weak-MAC probes force a ctr cipher on purpose: with an AEAD cipher
# (chacha20/GCM) OpenSSH skips MAC selection entirely, so a weak MAC only
# ever bites on ctr — that nuance is why the Ciphers pin alone would not
# close this door.
crypto_probe() { ssh "${OPTS[@]}" -i "$KEY" "$@" opsadmin@127.0.0.1 true 2>&1; }
out=$(crypto_probe -o Ciphers=aes256-ctr -o MACs=hmac-sha1 || true)
case "$out" in
  *"no matching MAC"*) pass "hmac-sha1 is refused at negotiation (no matching MAC)" ;;
  *)                   fail "hmac-sha1 is refused at negotiation (no matching MAC)" ;;
esac
# A refusal only means something next to an acceptance — same client, same
# ctr cipher, a strong MAC: the door is the algorithm, not the cipher.
if crypto_probe -o Ciphers=aes256-ctr -o MACs=hmac-sha2-512-etm@openssh.com >/dev/null 2>&1; then
  pass "the same ctr cipher with a strong MAC still logs in"
else
  fail "the same ctr cipher with a strong MAC still logs in"
fi
# Post-quantum hybrid negotiates for real. The VENDOR spelling on purpose:
# the IANA name sntrup761x25519-sha512 only exists in clients >= 9.9, and
# the CI runner's ssh is 9.6 — it knows only the @openssh.com name (there
# since 8.5). The server pins both, so the probe must speak the older one
# (the Bash twin's CI caught this exact probe failing under the IANA name).
if crypto_probe -o KexAlgorithms=sntrup761x25519-sha512@openssh.com >/dev/null 2>&1; then
  pass "post-quantum hybrid kex (sntrup761x25519) negotiates"
else
  fail "post-quantum hybrid kex (sntrup761x25519) negotiates"
fi
out=$(crypto_probe -o KexAlgorithms=ecdh-sha2-nistp256 || true)
case "$out" in
  *"no matching key exchange"*) pass "NIST P-curve kex is refused at negotiation" ;;
  *)                            fail "NIST P-curve kex is refused at negotiation" ;;
esac

echo "== Role 36: legacy protocol purge (CIS 2.2/2.3) =="
# Present means present as dpkg sees it: installed OR config-files (a
# removed-but-not-purged package still leaves its config behind). The list
# mirrors legacy_protocol_packages in the role — both halves of every
# transitional pair, because removing `telnet` alone leaves inetutils-telnet
# (and /usr/bin/telnet) behind.
legacy_present=""
for p in telnet inetutils-telnet telnetd inetutils-telnetd \
         rsh-client rsh-redone-client rsh-server rsh-redone-server \
         talk inetutils-talk talkd inetutils-talkd \
         nis tftp tftpd atftp atftpd tftp-hpa tftpd-hpa \
         xinetd openbsd-inetd inetutils-inetd; do
  st=$(on_node dpkg-query -W -f "'\${db:Status-Status}'" "$p" 2>/dev/null) || true
  case "$st" in installed|config-files) legacy_present="$legacy_present $p";; esac
done
if [ -z "$legacy_present" ]; then
  pass "no legacy protocol package survives (22 names checked, dpkg state)"
else
  fail "legacy protocol packages still present:$legacy_present"
fi
# And as PATH sees it — the planted telnet was a transitional package whose
# payload lives under another name, so the binary going away is its own check.
expect_ok "telnet/rsh/tftp binaries are gone from PATH" \
  bash -c "'! command -v telnet && ! command -v rsh && ! command -v tftp'"

echo "== Role 37: filesystem protections (CIS 1.5.x) =="
# The EFFECTIVE kernel values (the drop-in is the promise, the live knob the
# proof). The e2e plants all four weak first, so a pass here is real work.
expect_line "fs.protected_symlinks is on"  '^1$' sudo sysctl -n fs.protected_symlinks
expect_line "fs.protected_hardlinks is on" '^1$' sudo sysctl -n fs.protected_hardlinks
expect_line "fs.protected_fifos is on"     '^1$' sudo sysctl -n fs.protected_fifos
expect_line "fs.protected_regular is 2 (the strong setting)" '^2$' sudo sysctl -n fs.protected_regular
expect_line "the fs-protection drop-in is present and root-owned 0644" '^644 root root$' \
  "sudo stat -c '%a %U %G' /etc/sysctl.d/99-hardening-fs.conf"

# LAST on purpose: banning the client cuts our own SSH access to the node.
# Lift the shield installed at the top — from here on we WANT to be bannable.
docker exec dh-test-node fail2ban-client set sshd delignoreip 172.17.0.1 >/dev/null 2>&1 || true
echo "== Account database hygiene =="
# The CI plants two data-level logins before hardening (both measured on a
# stock node): dhnopw with an EMPTY password — Debian ships pam_unix with
# `nullok`, so pressing Enter authenticated — and dhlegacy with its hash
# sitting in world-readable /etc/passwd, which pam_unix also accepts. Plus
# a legacy NIS '+' entry in each of passwd/shadow/group.
expect_ok "no NIS compat ('+'/'-') entries survive in the account database" \
  "! sudo grep -qE '^[+-]' /etc/passwd /etc/shadow /etc/group"
expect_ok "every /etc/passwd password field is a shadow pointer ('x')" \
  "awk -F: '\$2 != \"x\" {exit 1}' /etc/passwd"
expect_line "the planted passwd-file hash now lives in /etc/shadow" '^\$y\$' \
  "sudo awk -F: '\$1 == \"dhlegacy\" {print \$2}' /etc/shadow"
# Moved, not broken: the SAME password planted before hardening must still
# authenticate after the migration — pwconv relocates the hash, it doesn't
# reset the account.
expect_ok "the migrated password still authenticates (moved, not broken)" \
  "printf 'Sh4dow-Migr8-OK!9\n' | sudo pamtester login dhlegacy authenticate"
expect_line "the empty-password account is locked ('!') in /etc/shadow" '^!' \
  "sudo awk -F: '\$1 == \"dhnopw\" {print \$2}' /etc/shadow"
# Behavioral crown: before hardening, pressing Enter WAS dhnopw's password
# (measured); the lock must have closed that door.
if on_node "printf '\n' | sudo pamtester login dhnopw authenticate" >/dev/null 2>&1; then
  fail "pressing Enter is no longer a password (empty-password account locked)"
else
  pass "pressing Enter is no longer a password (empty-password account locked)"
fi

echo "== Exploit mitigations =="
expect_line "full ASLR is in effect (randomize_va_space = 2)" '^2$' \
  sudo sysctl -n kernel.randomize_va_space
# Behavioral crown: with ASLR planted off, two fresh processes report the
# SAME stack base (measured while planting — the CI logs it); with full
# ASLR back on they must differ. /proc/self resolves inside each grep, so
# every probe is a brand-new address space.
stack_a=$(on_node "grep -m1 '\\[stack\\]' /proc/self/maps | cut -d- -f1" 2>/dev/null)
stack_b=$(on_node "grep -m1 '\\[stack\\]' /proc/self/maps | cut -d- -f1" 2>/dev/null)
if [ -n "$stack_a" ] && [ "$stack_a" != "$stack_b" ]; then
  pass "two fresh processes land on different stack addresses (ASLR is real)"
else
  fail "two fresh processes land on different stack addresses (got '$stack_a' twice)"
fi
expect_line "kexec into a replacement kernel is disabled (one-way latch)" '^1$' \
  sudo sysctl -n kernel.kexec_load_disabled
expect_line "unprivileged BPF is off and latched (one-way)" '^1$' \
  sudo sysctl -n kernel.unprivileged_bpf_disabled
# Not every kernel exposes the JIT knob (the WSL lab kernel doesn't —
# measured): where it exists it must be 2; where it doesn't, the drop-in
# still carries the pin for kernels that do.
jit=$(on_node "sudo sysctl -n net.core.bpf_jit_harden 2>/dev/null" 2>/dev/null || true)
if [ -z "$jit" ]; then
  pass "bpf_jit_harden not exposed by this kernel — pinned in the drop-in regardless"
elif [ "$jit" = 2 ]; then
  pass "the BPF JIT is blinded for every user (bpf_jit_harden = 2)"
else
  fail "bpf_jit_harden should be 2, got $jit"
fi
expect_line "perf events are root-only (perf_event_paranoid = 3)" '^3$' \
  sudo sysctl -n kernel.perf_event_paranoid
expect_line "the exploit-mitigation drop-in survives reboots" \
  'kernel\.randomize_va_space = 2' sudo cat /etc/sysctl.d/99-hardening-exploit.conf

echo "== tmp_confinement: /tmp is a dead end =="
expect_line "fstab pins /tmp with nodev,nosuid,noexec" \
  "nodev,nosuid,noexec" \
  grep -E "'^[^#].*[[:space:]]/tmp[[:space:]]'" /etc/fstab
expect_line "/tmp is live-mounted nodev" ",nodev,|,nodev$|^nodev," findmnt -no OPTIONS /tmp
expect_line "/tmp is live-mounted nosuid" ",nosuid,|,nosuid$|^nosuid," findmnt -no OPTIONS /tmp
expect_line "/tmp is live-mounted noexec" ",noexec,|,noexec$|^noexec," findmnt -no OPTIONS /tmp
# Functional: the dropper's move — stage a binary in the one world-writable
# directory every process can reach, run it from there. Must die on noexec.
on_node cp /bin/true /tmp/dh-ansible-probe 2>/dev/null || true
if on_node /tmp/dh-ansible-probe >/dev/null 2>&1; then
  fail "a binary staged in /tmp cannot execute (noexec enforced)"
else
  pass "a binary staged in /tmp cannot execute (noexec enforced)"
fi
on_node rm -f /tmp/dh-ansible-probe 2>/dev/null || true
# The measurement the role's story rests on: mount_options once left /tmp
# alone claiming noexec /tmp "breaks installers". Reinstall a real package —
# download, unpack, maintainer scripts, the works — on the confined node:
# apt and dpkg never execute from /tmp, and this proves it every CI run.
expect_ok "apt still installs packages with /tmp noexec (bsdutils reinstalled)" \
  sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y bsdutils

echo "== time_sync: the clock is a security control =="
expect_ok "systemd-timesyncd is installed" dpkg -s systemd-timesyncd
expect_line "the drop-in pins explicit NTP servers" \
  '^NTP=.*debian\.pool\.ntp\.org' sudo cat /etc/systemd/timesyncd.conf.d/99-hardening.conf
expect_line "systemd-timesyncd is enabled at boot" '^enabled$' sudo systemctl is-enabled systemd-timesyncd
# The honesty fork, measured while designing the role: timesyncd ships
# ConditionVirtualization=!container - in a container systemd itself keeps
# the unit inactive BY DESIGN (one kernel clock, and it belongs to the
# host). ConditionResult reads over systemd's private socket, no dbus.
if on_node systemd-detect-virt --container --quiet 2>/dev/null; then
  expect_line "container: systemd skips timesyncd via its own condition (the honest skip, not a crash)" \
    '^ConditionResult=no$' sudo systemctl show systemd-timesyncd -p ConditionResult
else
  expect_line "systemd-timesyncd is active" '^active$' sudo systemctl is-active systemd-timesyncd
  synced=no
  for _ in $(seq 1 30); do
    if on_node test -f /run/systemd/timesync/synchronized 2>/dev/null; then synced=yes; break; fi
    sleep 2
  done
  if [ "$synced" = yes ]; then
    pass "the clock actually synchronized (/run/systemd/timesync/synchronized exists)"
  else
    fail "the clock actually synchronized (/run/systemd/timesync/synchronized exists)"
  fi
fi

echo "== apt_trust: the package manager's trust gates =="
expect_line "the apt trust drop-in pins AllowInsecureRepositories false" \
  '^Acquire::AllowInsecureRepositories "false";' sudo cat /etc/apt/apt.conf.d/99-hardening-apt-trust
# Effective, not just written: apt-config dump is apt's merged view of every
# conf file - the `sshd -T` of apt - so it shows whether the 99- pin actually
# beat the loosening the CI planted in an EARLIER file (apt.conf.d is read in
# lexical order, last setting wins).
expect_line "effective config: unsigned repositories refused (the planted 90-weak loosening is overridden)" \
  '^Acquire::AllowInsecureRepositories "false";' apt-config dump
expect_line "effective config: unauthenticated installs refused" \
  '^APT::Get::AllowUnauthenticated "false";' apt-config dump
expect_line "effective config: expired Release files refused (Check-Valid-Until)" \
  '^Acquire::Check-Valid-Until "true";' apt-config dump
# Behavioural, both gates, against a repository built on the node with NO
# Release file (a hand-made .deb + Packages index, no network needed), with
# apt's directories redirected so the real lists and cache stay untouched:
#  1. the INDEX gate: apt-get update must refuse the repo, and the same probe
#     with the gate opened on the command line must succeed - a refusal only
#     means something next to an acceptance (it proves the repo was fine);
#  2. the INSTALL gate: with the index fetched through the opened gate (the
#     stale-list scenario), a REAL install must be refused as unauthenticated.
#     Measured: `apt-get -s` (simulate) prints "Inst" and exits 0 regardless,
#     so a dry run cannot carry this check - only the real call does.
# World-readable on purpose: apt fetches file:// as the _apt user, and the
# umask role (027) would otherwise hide the probe from it.
on_node sudo bash -s <<'SH' >/dev/null 2>&1 || true
set -e
umask 022
d=/tmp/dh-apt-probe
rm -rf "$d"
mkdir -p "$d/pkg/DEBIAN" "$d/pkg/usr/share/doc/dh-apt-probe" "$d/lists/partial" "$d/archives/partial"
printf 'Package: dh-apt-probe\nVersion: 1.0\nArchitecture: all\nMaintainer: probe <probe@localhost>\nDescription: apt trust probe (verify.sh, harmless)\n' > "$d/pkg/DEBIAN/control"
echo probe > "$d/pkg/usr/share/doc/dh-apt-probe/README"
dpkg-deb -b "$d/pkg" "$d/dh-apt-probe_1.0_all.deb" >/dev/null
cd "$d"
{ dpkg-deb -f dh-apt-probe_1.0_all.deb
  printf 'Filename: ./dh-apt-probe_1.0_all.deb\nSize: %s\nSHA256: %s\n' "$(stat -c %s dh-apt-probe_1.0_all.deb)" "$(sha256sum dh-apt-probe_1.0_all.deb | cut -d' ' -f1)"
} > Packages
echo "deb [arch=all] file:$d ./" > "$d/probe.list"
chmod -R a+rX "$d"
SH
probe_opts=(-o Dir::Etc::SourceList=/tmp/dh-apt-probe/probe.list -o Dir::Etc::SourceParts=/nonexistent
            -o Dir::State::Lists=/tmp/dh-apt-probe/lists -o Dir::Cache::Archives=/tmp/dh-apt-probe/archives)
if on_node sudo apt-get update "${probe_opts[@]}" >/dev/null 2>&1; then
  fail "a repository with no Release file is refused at apt-get update (index gate)"
else
  pass "a repository with no Release file is refused at apt-get update (index gate)"
fi
expect_ok "...and the same probe with the gate opened on the command line succeeds (the repo itself was fine)" \
  sudo apt-get update "${probe_opts[@]}" -o Acquire::AllowInsecureRepositories=true
if on_node sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${probe_opts[@]}" dh-apt-probe >/dev/null 2>&1; then
  fail "a package from the unsigned index is refused as unauthenticated (install gate, stale-list scenario)"
  on_node sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y dh-apt-probe >/dev/null 2>&1 || true
else
  pass "a package from the unsigned index is refused as unauthenticated (install gate, stale-list scenario)"
fi
on_node sudo rm -rf /tmp/dh-apt-probe 2>/dev/null || true

echo "== var_tmp_confinement: the persistent staging ground is a dead end =="
expect_line "fstab pins the /var/tmp bind with nodev,nosuid,noexec" \
  "bind,nodev,nosuid,noexec" \
  grep -E "'^[^#].*[[:space:]]/var/tmp[[:space:]]'" /etc/fstab
expect_ok "/var/tmp is a mountpoint of its own (the bind)" mountpoint -q /var/tmp
# A bind, not a tmpfs: the source is the root filesystem's own /var/tmp
# subtree (findmnt prints it as DEVICE[/var/tmp]) - the files persist.
expect_line "/var/tmp is bind-mounted from itself (persistence intact, not a tmpfs)" \
  '\[/var/tmp\]$' findmnt -no SOURCE /var/tmp
expect_line "/var/tmp is live-mounted nodev" ",nodev,|,nodev$|^nodev," findmnt -no OPTIONS /var/tmp
expect_line "/var/tmp is live-mounted nosuid" ",nosuid,|,nosuid$|^nosuid," findmnt -no OPTIONS /var/tmp
expect_line "/var/tmp is live-mounted noexec" ",noexec,|,noexec$|^noexec," findmnt -no OPTIONS /var/tmp
# Functional: the dropper's move against the directory that SURVIVES a
# reboot - stage a binary there, run it from there. Must die on noexec.
on_node cp /bin/true /var/tmp/dh-probe 2>/dev/null || true
if on_node /var/tmp/dh-probe >/dev/null 2>&1; then
  fail "a binary staged in /var/tmp cannot execute (noexec enforced)"
else
  pass "a binary staged in /var/tmp cannot execute (noexec enforced)"
fi
on_node rm -f /var/tmp/dh-probe 2>/dev/null || true

echo "== service_purge: the daemons nobody asked for are gone =="
# The CI installs avahi-daemon, cups (metapackage AND cups-daemon) and rpcbind
# on the node before the play, so each of these flips red-to-green from real
# work - and the cups-daemon line is the measured trap (purging `cups` alone
# leaves cupsd installed).
for pkg in avahi-daemon cups cups-daemon cups-browsed rpcbind; do
  if on_node dpkg -s "$pkg" >/dev/null 2>&1; then
    fail "$pkg is purged"
  else
    pass "$pkg is purged"
  fi
done
expect_ok "nothing listens on mDNS, IPP or the portmapper (5353/631/111)" \
  bash -c "'! ss -lntu | grep -E \":(5353|631|111)[[:space:]]\"'"

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
