#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Read-only: which sshd lines beat a drop-in's keywords.

Most sshd keywords are first-wins and Debian includes sshd_config.d at the
top of sshd_config, in lexical order - so a drop-in named before ours (the
50-cloud-init.conf Debian's cloud-init writes) or a main-file line above the
Include silently beats it. Two break the rule (measured on OpenSSH 10.0p2 and
9.2): MaxStartups is LAST-wins, so a line read after ours beats it - one
appended below the Include, or a drop-in sorting later - and AllowGroups adds
up from every file, before or after. Mirrors sshd_reclaim/sshd_confirm in the
Bash twin.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: sshd_shadows
short_description: Find sshd lines that beat a drop-in's keywords
description:
  - Lists every line that sets one of the keywords in O(lines) to a value that
    is not the drop-in's, from wherever that keyword can win - read before
    O(dropin) (the main config above its Include, drop-ins sorting first) for
    first-wins keywords, read after it (drop-ins sorting later, the main
    config below its Include) for MaxStartups, both for AllowGroups.
  - Each line carries its side, C(before) or C(after); the main config holds
    both, so a caller editing by text picks the first match for a C(before)
    line and the last for an C(after) one.
  - Lines from a file's first Match on are never listed (a Match applies per
    connection). Port lines are reported apart - another listening port may
    be someone's way in, so the caller names it and leaves it.
  - With O(confirm), also asks C(sshd -T) for the effective value of every
    single-valued keyword and reports the ones that still lose.
  - Never changes anything.
options:
  dropin:
    description: The drop-in whose keywords must win.
    type: path
    required: true
  lines:
    description: The C(Keyword value) lines the drop-in enforces.
    type: list
    elements: str
    required: true
  main_config:
    description: The main sshd config.
    type: path
    default: /etc/ssh/sshd_config
  dropin_dir:
    description: The directory the main config includes.
    type: path
    default: /etc/ssh/sshd_config.d
  confirm:
    description: Also compare C(sshd -T) with O(lines).
    type: bool
    default: false
"""

RETURN = r"""
shadows:
  description: Lines to reclaim (path, line, raw, keyword, side).
  returned: always
  type: list
ports:
  description: Port lines with another port, either side (named, never cut).
  returned: always
  type: list
still_loses:
  description: With confirm, keywords whose effective value is not the drop-in's.
  returned: always
  type: list
"""

import glob
import os
import re

from ansible.module_utils.basic import AnsibleModule

# These accumulate across the files sshd reads instead of being first-wins,
# so a single effective value cannot be compared (verify checks them as sets).
ACCUMULATING = ("port", "hostkey", "allowgroups")
# From which side of the drop-in a line beats it: an accumulating keyword
# from both, MaxStartups (last-wins) from after, everything else from before.
LAST_WINS = ("maxstartups",)


def beats_from(keyword):
    if keyword in ACCUMULATING:
        return ("before", "after")
    if keyword in LAST_WINS:
        return ("after",)
    return ("before",)
KEYWORD = re.compile(r"([^\s=]+)\s*=?\s*(.*)$")


def split_line(text):
    match = KEYWORD.match(text.strip())
    if not match:
        return None, None
    return match.group(1).lower(), " ".join(match.group(2).split()).lower()


def global_lines(path, piece):
    """Lines outside Match blocks. piece: "all" for a drop-in; "above" or
    "below" the Include for the main config, read before and after the
    drop-ins."""
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()
    except (IOError, OSError):
        return []
    found = []
    below = False
    for number, raw in enumerate(lines, 1):
        low = raw.strip().lower()
        if re.match(r"match(\s|$)", low):
            break
        if piece != "all" and re.match(r"include\s", low):
            if piece == "above":
                break
            below = True
            continue
        if piece == "below" and not below:
            continue
        if not low or low.startswith("#"):
            continue
        found.append((number, raw))
    return found


def main():
    module = AnsibleModule(
        argument_spec=dict(
            dropin=dict(type="path", required=True),
            lines=dict(type="list", elements="str", required=True),
            main_config=dict(type="path", default="/etc/ssh/sshd_config"),
            dropin_dir=dict(type="path", default="/etc/ssh/sshd_config.d"),
            confirm=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )
    params = module.params
    want = {}
    for line in params["lines"]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        keyword, value = split_line(line)
        if keyword:
            want.setdefault(keyword, set()).add(value)

    base = os.path.basename(params["dropin"])
    # What sshd reads, in order: the main file above its Include, the
    # drop-ins (glob order: Python's sorted() is code-point order, the C
    # collation) - this one among them - then the main file below the Include.
    main_config = params["main_config"]
    has_main = os.path.isfile(main_config)
    pieces = [(main_config, "above", "before")] if has_main else []
    names = set(
        os.path.basename(path)
        for path in glob.glob(os.path.join(params["dropin_dir"], "*.conf"))
        if os.path.isfile(path)
    )
    names.add(base)
    side = "before"
    for name in sorted(names):
        if name == base:
            side = "after"
            continue
        pieces.append((os.path.join(params["dropin_dir"], name), "all", side))
    if has_main:
        pieces.append((main_config, "below", "after"))

    shadows, ports = [], []
    for path, piece, side in pieces:
        for number, raw in global_lines(path, piece):
            keyword, value = split_line(raw)
            if keyword not in want or value in want[keyword]:
                continue
            if side not in beats_from(keyword):
                continue
            hit = dict(path=path, line=number, raw=raw, keyword=keyword, side=side)
            (ports if keyword == "port" else shadows).append(hit)

    still_loses = []
    if params["confirm"]:
        rc, out, err = module.run_command(["sshd", "-T"])
        if rc != 0:
            module.fail_json(msg="sshd -T failed: %s" % err.strip())
        effective = {}
        for line in out.splitlines():
            keyword, value = split_line(line)
            if keyword and keyword not in effective:
                effective[keyword] = value
        for keyword, values in sorted(want.items()):
            if keyword in ACCUMULATING:
                continue
            if effective.get(keyword) not in values:
                still_loses.append(
                    dict(keyword=keyword, written=sorted(values)[0], effective=effective.get(keyword))
                )

    module.exit_json(changed=False, shadows=shadows, ports=ports, still_loses=still_loses)


if __name__ == "__main__":
    main()
