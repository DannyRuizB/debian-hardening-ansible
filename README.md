# debian-hardening-ansible

> The same Debian baseline as my [debian-hardening](https://github.com/DannyRuizB/debian-hardening)
> Bash script — a sudo user with your SSH key, key-only SSH, a UFW firewall,
> Fail2Ban and automatic security updates — but rebuilt **the Ansible way**:
> declarative, role-based and idempotent, **without locking you out**.

[![lint](https://github.com/DannyRuizB/debian-hardening-ansible/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/debian-hardening-ansible/actions/workflows/lint.yml)
[![e2e](https://github.com/DannyRuizB/debian-hardening-ansible/actions/workflows/test.yml/badge.svg)](https://github.com/DannyRuizB/debian-hardening-ansible/actions/workflows/test.yml)
![Ansible](https://img.shields.io/badge/Ansible-EE0000?logo=ansible&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?logo=debian&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

## Why

I first wrote this baseline as a single Bash script. This repo is the same job
done as **Infrastructure as Code**: instead of imperative commands with my own
hand-rolled idempotency checks, each step declares the *desired state* and
Ansible decides what (if anything) to change. Re-running it is a no-op when the
host is already compliant, and it scales to many servers from one inventory.

It's a small, readable project meant to show I can take a manual procedure and
express it cleanly in Ansible — roles, variables, templates, handlers and
conditionals — not just run ad-hoc commands.

## What it does

Five roles, applied in order by `site.yml`:

| Role | Detail |
|---|---|
| **admin_user** | Optional: create a sudo user and install their SSH public key (runs first, so the SSH lockout guard can find a key). |
| **ssh_hardening** | Drop-in `99-hardening.conf`: no root login, key-only auth, custom port. `validate: sshd -t` before the file goes live; reloads SSH only on change. |
| **ufw** | Default deny incoming, allow SSH (and any extra ports), then enable. |
| **fail2ban** | `sshd` jail, `backend = systemd`, `banaction = ufw`, ban 1h / maxretry 5. |
| **unattended_upgrades** | Automatic security patches. |

### Lockout guard

The `ssh_hardening` role **will not disable password authentication** unless it
finds a non-empty `authorized_keys` for the connecting user — so a missing or
mistyped key can't lock you out. Install a key via the `admin_user` role, or set
`ssh_force_no_password: true` only when you have console access.

## What this demonstrates

- **Infrastructure as Code** — a real manual procedure expressed declaratively
  in idiomatic Ansible: roles, `defaults`, Jinja2 templates, handlers, loops and
  conditionals.
- **Idempotency by design** — desired-state modules instead of hand-written
  `if` checks; a second run reports `ok`, not `changed`.
- **Safe automation** — config validated with `sshd -t` *before* it replaces the
  live file, SSH reloaded only when it actually changed, and a lockout safeguard.
- **Linux security baseline** — SSH hardening, host firewall, brute-force
  protection and patch automation.

## Usage

```bash
git clone https://github.com/DannyRuizB/debian-hardening-ansible.git
cd debian-hardening-ansible

# 1. Point the inventory at your server (edit ansible_host / ansible_user).
$EDITOR inventory.ini

# 2. Dry-run: show every change without touching the host.
ansible-playbook site.yml --check --diff \
  -e admin_user_name=danny \
  -e "admin_user_pubkey='$(cat ~/.ssh/id_ed25519.pub)'"

# 3. Apply for real.
ansible-playbook site.yml \
  -e admin_user_name=danny \
  -e "admin_user_pubkey='$(cat ~/.ssh/id_ed25519.pub)'"
```

### Common variables

Override on the command line (`-e var=value`) or in `group_vars/`:

| Variable | Default | Meaning |
|---|---|---|
| `ssh_port` | `22` | SSH port; shared by the SSH, UFW and Fail2Ban roles (`group_vars/all.yml`). |
| `admin_user_name` | `""` | Sudo user to create (empty = skip the role). |
| `admin_user_pubkey` | `""` | Public key to install for that user. |
| `admin_user_passwordless_sudo` | `true` | Give that user passwordless sudo (they have no password, so otherwise can't escalate). Set `false` if you manage their password yourself. |
| `ufw_extra_ports` | `[]` | Extra ports to open, e.g. `'["80/tcp","443/tcp"]'`. |
| `ssh_hardening_force_no_password` | `false` | Disable password auth even with no key (DANGEROUS). |

## How it's tested

Linting is not testing, so on every push the [`e2e` workflow](.github/workflows/test.yml)
**applies the hardening for real** and checks the result from the outside:

1. **Boot a disposable "server"** — a privileged systemd container
   (Debian 13 + sshd) where root logs in with a CI key, like a fresh VPS
   ([`tests/node.sh`](tests/node.sh)).
2. **Dry-run first** — `site.yml --check` against the fresh node must succeed
   without touching it.
3. **First pass as root** — the playbook creates the admin user, locks down
   SSH, enables UFW, Fail2Ban and unattended-upgrades.
4. **Second pass as the admin user** — root is locked out now, so this pass
   connects as the user the playbook just created (proving the handover), and
   must report `changed=0` (proving idempotence).
5. **Verify from the outside** ([`tests/verify.sh`](tests/verify.sh)) — every
   promise, checked over SSH like an attacker would: root login rejected,
   password auth not offered (and `sshd -T` effective config), UFW active with
   deny-by-default, services running — and finally a live brute-force
   simulation that must get the client **banned by Fail2Ban**.

### Red-team experiment

For fun (and as a sharper proof), [`tests/redteam.sh`](tests/redteam.sh) turns
the tables: instead of asserting the config, it **attacks** the hardened node
from the outside — handing the attacker a valid key *and* the correct account
passwords — and records what the server does. Root logins with a valid key,
password auth with the right password, and a brute-force burst are all turned
away; the write-up is in [`tests/REDTEAM.md`](tests/REDTEAM.md).

Its blue-team counterpart, [`tests/forensics.sh`](tests/forensics.sh), stages an
attack and then **reconstructs it from the node's own logs** — who attacked,
which accounts they tried, and how Fail2Ban responded — as a tour of the files a
defender actually reads ([`tests/FORENSICS.md`](tests/FORENSICS.md)).

And [`tests/before_after.sh`](tests/before_after.sh) runs the **same attack
against a stock Debian node and a hardened one, side by side** — the stock box
is breached as root in one guess and brute-forced without limit, the hardened
one refuses both ([`tests/BEFORE_AFTER.md`](tests/BEFORE_AFTER.md)).

The same harness runs locally with Docker:

```bash
./tests/node.sh up && ./tests/node.sh wait
echo "admin_user_pubkey: '$(cat tests/.ssh_ci/id_ci.pub)'" > tests/.ssh_ci/pubkey.yml
ansible-playbook -i tests/inventory_first_run.ini site.yml -e @tests/vars_ci.yml -e @tests/.ssh_ci/pubkey.yml
ansible-playbook -i tests/inventory_hardened.ini site.yml -e @tests/vars_ci.yml -e @tests/.ssh_ci/pubkey.yml
./tests/verify.sh
./tests/node.sh down
```

## Verify after running

```bash
ssh user@host 'sshd -T | grep -Ei "passwordauth|permitroot|^port"'
ssh user@host 'sudo ufw status verbose'
ssh user@host 'sudo fail2ban-client status sshd'
```

## Requirements

- **Control node:** Ansible (`pipx install --include-deps ansible`). Uses the
  `community.general` and `ansible.posix` collections (bundled with the full
  `ansible` package).
- **Managed node:** Debian 12 (Bookworm) or 13 (Trixie), reachable over SSH with
  a sudo-capable user.

> ⚠️ Run with `--check --diff` first, and on a host you can reach by console
> (e.g. the Proxmox/hypervisor shell) the first time, in case of a custom SSH
> setup.

## About

Built by **[Danny Ruiz](https://github.com/DannyRuizB)** — systems & network
administrator (ASIR, *Administración de Sistemas Informáticos en Red*).
[More projects →](https://github.com/DannyRuizB?tab=repositories)

## License

MIT — see [LICENSE](LICENSE).
