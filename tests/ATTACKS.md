# Attack catalogue — the recon & login toolkit, and why it bounces

A tour of the moves an attacker actually runs against an SSH box, each aimed at
the hardened node. Where `redteam.sh` proves the box holds and `before_after.sh`
contrasts it with a stock one, [`attacks.sh`](attacks.sh) walks the *toolkit* —
what each technique is, what it's fishing for, and the control that neutralises
it.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait
echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
ansible-playbook -i inventory_first_run.ini ../site.yml -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
./attacks.sh
```

## The four techniques

| # | Technique | What the attacker wants | Result on the hardened node | Mitigated by |
|---|-----------|------------------------|----------------------------|--------------|
| 1 | **Banner grabbing** | the OpenSSH version, to look up CVEs | version *does* leak (`OpenSSH_10.0p2 Debian`) | patching (`unattended_upgrades`) |
| 2 | **Port scan** | open services to attack | only `22` answers; everything else filtered | UFW default-deny |
| 3 | **Username enumeration** | which accounts are real, to target | every user → identical `Permission denied (publickey)` | key-only sshd |
| 4 | **Dictionary attack** | a weak password → a shell | 16 passwords tried, 0 cracked — never even read | `PasswordAuthentication no` |

## What each result teaches

**Banner grabbing is the one thing the box does give up.** The SSH greeting
advertises the exact version, and that's normal — hiding it is security by
obscurity. The honest defence isn't to lie about the version, it's to *not be
running a vulnerable one*, which is why automatic security updates are part of
the baseline.

**A port scan of a hardened host is boring, and that's the point.** UFW's
default-deny turns every port except 22 into a silent drop, so the attacker's
map comes back nearly empty. No exposed database, no forgotten web admin panel —
nothing to pivot through.

**Username enumeration finds nothing because sshd treats everyone the same.**
Real user, `root`, or a name typed at random all get the byte-identical
`Permission denied (publickey)`. A misconfigured server can leak valid usernames
through different error messages or response times; this one doesn't.

**The dictionary attack is dead on arrival.** With password auth disabled the
server never reads the password at all, so the list's length is irrelevant —
zero of anything times a million is still zero. On a stock node with password
auth on, this *same* short list is precisely how internet-facing boxes get
owned; see [`BEFORE_AFTER.md`](BEFORE_AFTER.md) for that node getting breached.

## Honesty

This is a *catalogue*, not an exploit framework: recon with `nc` and OpenSSH,
not `nmap`/`hydra`, and it stops at the login layer. It shows how the baseline's
controls each blunt a specific class of technique — not that the host is immune
to everything (kernel or service CVEs, post-access privilege escalation, and
supply-chain attacks are all out of scope).
