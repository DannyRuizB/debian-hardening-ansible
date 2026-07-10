# Before / after — the same attack against stock vs hardened

The clearest way to see what the hardening buys you: run the **same attack**
against a stock Debian node and a hardened one, side by side.
[`before_after.sh`](before_after.sh) spins up a stock "vulnerable" node next to
the hardened one and attacks both identically.

The stock node is the same image with a default SSH config — root login on,
password auth on, a weak root password (`root:toor`), no firewall, no Fail2Ban.
A fresh VPS before anyone touched it.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait
echo "admin_user_pubkey: '$(cat .ssh_ci/id_ci.pub)'" > .ssh_ci/pubkey.yml
ansible-playbook -i inventory_first_run.ini ../site.yml -e @vars_ci.yml -e @.ssh_ci/pubkey.yml
./before_after.sh     # brings up the stock node, attacks both, tears it down
```

## The result

```
  Attack / probe                     | STOCK node         | HARDENED node
  ---------------------------------- | ------------------ | ------------------
  root login w/ weak password 'toor' | >> BREACHED (in)   | refused
  auth methods offered               | publickey,password | publickey
  brute force (12 tries) ->          | no limit, no ban   | banned after 5
```

Same attacker, same commands, opposite outcome:

- **The password login** breaks the stock node in a single guess — root is
  reachable and the password is weak. The hardened node never accepts a
  password: `sshd` only offers `publickey`, so there is nothing to guess.
- **`PermitRootLogin` + `PasswordAuthentication`** are the two lines that flip
  the first row. On the stock node they are on; the `ssh_hardening` role turns
  both off.
- **Brute force is unlimited on the stock node** — no firewall, no Fail2Ban, so
  an attacker can try passwords forever. On the hardened node Fail2Ban bans the
  source after 5 tries and UFW drops it.

## How the attack stays honest

Every probe is run identically against both ports — the only variable is the
hardening. The password login uses SSH's `SSH_ASKPASS` helper (no `sshpass`
needed); auth methods come straight from `ssh -v`; the brute-force verdict is
read from the outside (a transport reset = banned, a normal `publickey` denial =
still reachable), so it reflects what a real attacker would observe, not an
inside peek.

## Honesty

The weak `root:toor` password is deliberately terrible to make the first row
land in one guess; a real attacker would need a dictionary, but the stock node
gives them unlimited tries to run it — which is the whole point. This compares
*these five controls*, not a full OS baseline.
