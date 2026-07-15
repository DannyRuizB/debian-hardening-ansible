# Compliance audit — grading the node against a CIS-style checklist

[`audit.sh`](audit.sh) scores the hardened node against a broader checklist than
`verify.sh` uses. `verify.sh` confirms *the baseline was applied*; this grades a
wider set of best practices — deliberately including ones the baseline may not
cover — so the score is honest and any failures read as a to-do list.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait
echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
ansible-playbook -i inventory_first_run.ini ../site.yml -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
./audit.sh
```

## Grading

Each check is `PASS` (control in place), `WARN` (a CIS hardening not applied —
improvable) or `FAIL` (a core control missing — serious). The score weights
`WARN` as a half-point:

```
Score = (PASS + 0.5*WARN) / total * 100
```

Categories: SSH authentication (core), SSH hardening extras (CIS), firewall,
intrusion prevention, patch management, kernel parameters (CIS network),
account policies (CIS), filesystem mount options (CIS), and accounts & files.

## What it caught — and the fix

On first run the baseline scored **89% (14 PASS, 4 WARN, 0 FAIL)**. Zero core
failures, but four CIS extras that the SSH drop-in didn't set:

| WARN | Was | CIS wants |
|---|---|---|
| `MaxAuthTries` | 6 | ≤ 4 |
| `X11Forwarding` | yes | no |
| `LoginGraceTime` | 120 | ≤ 60 |
| `ClientAliveInterval` | 0 (no idle timeout) | 300 |

So the audit became a to-do list, and the `ssh_hardening` role now sets all
four (as tunable variables in the role's `defaults/`). Re-running the playbook
and the audit:

```
 Score: 18 PASS, 0 WARN, 0 FAIL  ->  100% compliant
```

Idempotence held (a follow-up run is `changed=0`) and the e2e `verify.sh` still
passes — the extra directives tighten the config without changing key-only
behaviour. That's the whole loop: **audit → find gaps → remediate → re-audit.**

When the baseline later gained the `sysctl_hardening` role, the audit grew with
it: a **Kernel parameters (CIS network)** section now grades seven of the keys
the role's drop-in promises (ICMP redirects, source routing, rp_filter, SYN
cookies, `dmesg_restrict`, `suid_dumpable`). The `account_policies` role added
an **Account policies (CIS)** section with four more: password max/min age,
expiry warning, and the inactivity lock for new accounts. The `mount_options`
role added a **Filesystem mount options (CIS)** section with four more:
`/dev/shm` mounted `nodev` / `nosuid` / `noexec`, plus the fstab pin that makes
the options survive a reboot. Current score on a freshly hardened node:

```
 Score: 33 PASS, 0 WARN, 0 FAIL  ->  100% compliant
```

## Honesty

This is a lightweight, SSH-and-service-focused checklist, not a full CIS
Benchmark or a Lynis run. 100% here means "compliant with *these* checks" — it
doesn't cover auditd, AppArmor,
or the dozens of other items a full benchmark grades. It's a useful, honest
scorecard for the controls this baseline is actually responsible for.
