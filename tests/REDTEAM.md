# Red-team report — attacking the hardened node

This is the adversarial companion to the e2e test. Where
[`verify.sh`](verify.sh) *asserts* the configuration, [`redteam.sh`](redteam.sh)
**attacks** a freshly hardened node from the outside and records what the
server does. Everything runs locally: the target is the throwaway systemd
container from [`node.sh`](node.sh) on `127.0.0.1:2222`, attacked from the
same machine.

To make it a fair fight, the attacker is handed the strongest possible
position: an SSH key of their own **and** the correct account passwords
(`opsadmin:SuperSecret123`, `root:ToorRoot456`). The hardening still has to
turn every attempt away.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait
echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
ansible-playbook -i inventory_first_run.ini ../site.yml \
    -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
./redteam.sh
./node.sh down
```

## What gets attacked, and the result

| # | Attack | What the server did | Verdict |
|---|--------|--------------------|---------|
| Control | Legit admin logs in with their key | In, with working sudo | ✅ access preserved |
| 1 | `root` with a **valid** authorized key | `Permission denied (publickey)` — `PermitRootLogin no` overrides the key | 🛡️ blocked |
| 2 | `opsadmin` with an **unauthorized** key | `Permission denied (publickey)` | 🛡️ blocked |
| 3 | `root` with an unauthorized key | `Permission denied (publickey)` | 🛡️ blocked |
| 4 | Login as a non-existent user `hacker` | `Permission denied (publickey)` | 🛡️ blocked |
| 5 | Password auth with the **correct** password | Server offers only `publickey` — it never even prompts | 🛡️ blocked |
| 6 | Brute force: waves of failed logins | Fail2Ban bans the source IP after 5 tries | 🛡️ blocked |
| 7 | Banned IP retries with a **valid** key | Rejected at the firewall (`Connection reset`) before SSH is reached | 🛡️ blocked |
| Recovery | Admin unbans + restarts Fail2Ban | Access restored | ✅ reversible |

**Result: 7 attacks repelled, 0 leaks.**

## The three findings worth remembering

**A valid key is not enough for root.** In attack #1 the CI key *is* present in
`/root/.ssh/authorized_keys`, yet the login is refused. `PermitRootLogin no` is
evaluated before the key — hardening beats a leaked root key.

**Knowing the password buys nothing.** The server advertises exactly one method,
`publickey`, so in attack #5 it closes the connection without ever prompting for
the password the attacker already knows. There is no password prompt to brute
force.

**A ban outlives a good key, on purpose.** Fail2Ban's block is a UFW `REJECT`
rule at the firewall (`banaction = ufw`), so in attack #7 the packet is reset
before `sshd` sees it — even though the key is valid. And a plain unban isn't
enough to recover: the ban still has time on its 1-hour clock and the recent
failures are inside the 10-minute `findtime` window, so Fail2Ban re-bans on the
next tick. The realistic recovery is *unban + restart the service*, which clears
both the ban and the failure counter — exactly what the Recovery step does.

## Bonus: the firewall, end-to-end

Reachability was also checked against the node's real Docker-network IP (not
loopback, which UFW doesn't filter):

- port 22 (SSH, explicitly allowed) → **reachable**
- a service started on port 9090 (not allowed) → **blocked**
- after `ufw allow 9090/tcp`, the same service → **reachable** (proving it was
  the firewall, not a dead service), then closed again

## Notes and honesty

- The attacker's "source IP" is the Docker bridge gateway (`172.17.0.x`), the
  same for every attempt — realistic for a single-origin brute force, not a
  distributed one.
- Pausing Fail2Ban during phase 1–2 is deliberate: it isolates the SSH auth
  layer so those results measure `sshd` alone, not the firewall. Phase 3 turns
  it back on for its dedicated test.
- This proves the *configuration* resists these attacks. It is not a full
  penetration test (no kernel/service CVEs, no supply-chain, no local privilege
  escalation once inside).
