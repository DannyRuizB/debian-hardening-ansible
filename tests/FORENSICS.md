# Blue-team report — reading the logs after an attack

The red-team half (`redteam.sh`) *attacks* the node. This half is the defender's
answer: after an attack, [`forensics.sh`](forensics.sh) reconstructs what
happened **from the node's own logs** — the same files a real analyst opens
during incident response. Every section prints the source it reads, so it also
works as a map of *where Debian records this stuff*.

It is self-contained: it marks a start time, generates one legitimate login and
then an attack, and analyses only events after that mark — so the report never
mixes in the earlier Ansible provisioning (which legitimately logs in as root
before root login is disabled). It leaves the ban live so sections 4–5 show real
firewall state.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait
echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
ansible-playbook -i inventory_first_run.ini ../site.yml -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
./forensics.sh          # stages an attack and prints the incident report
./redteam.sh            # (optional) resets the ban afterwards, or:
./node.sh down
```

## What the report reconstructs

| Section | Question it answers | Source file |
|---|---|---|
| 1. Timeline | When did the attack start and end? | `journalctl -u ssh` |
| 2. Origin | Which IP(s) attacked, and how hard? | `journalctl -u ssh` |
| 3. Targets | Which usernames were tried? | `journalctl -u ssh` |
| 4. Defence | What did Fail2Ban ban, and when? | `/var/log/fail2ban.log` |
| 5. Firewall | What rule is blocking them right now? | `ufw status` |
| 6. Contrast | Who actually logged in successfully? | `journalctl -u ssh` |

## The log lines that tell the story

The report is just disciplined reading of a handful of patterns. Worth knowing
by sight:

| Log line | Meaning |
|---|---|
| `Invalid user oracle from 172.17.0.1` | attacker guessed a username that doesn't exist |
| `Connection closed by invalid user oracle … [preauth]` | …and gave up before authenticating |
| `Connection closed by authenticating user root … [preauth]` | a **real** account (root) tried with a key that failed |
| `Accepted publickey for opsadmin from …` | a successful login — this is the one to trust, and to alarm on if unexpected |
| `NOTICE [sshd] Ban 172.17.0.1` (in `fail2ban.log`) | Fail2Ban decided to block the source |
| `REJECT  172.17.0.1  # by Fail2Ban…` (in `ufw status`) | the live firewall rule doing the blocking |

## Two things this teaches

**Fail2Ban does not log to the journal.** Its ban decisions go to
`/var/log/fail2ban.log`, while `journalctl -u fail2ban` only shows the service
starting and stopping. A defender looking in the wrong place sees nothing —
this tripped up the first version of the script.

**Legitimate admin access looks different from an attack, but not by much.**
The provisioning step and the real admin both produce `Accepted publickey`
lines; only the *username* and *timing* separate them from a breach. That is
exactly why time-boxing the analysis (only events after a known-good mark)
matters — and why an unexpected `Accepted publickey for root` at 3 a.m. is the
line that should page someone.

## Honesty

This reads logs on a lab container after a self-inflicted attack. It is incident
*reconstruction*, not live detection — a real SOC would ship these same logs to
a SIEM and alert on the patterns in real time. The value here is learning to
read the raw sources before trusting a tool to read them for you.
