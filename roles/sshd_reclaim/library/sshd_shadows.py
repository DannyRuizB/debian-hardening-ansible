#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Read-only: which sshd lines read BEFORE a drop-in shadow its keywords.

Most sshd keywords are first-wins and Debian includes sshd_config.d at the
top of sshd_config, in lexical order - so a drop-in named before ours (the
50-cloud-init.conf Debian's cloud-init writes) or a main-file line above the
Include silently beats it. Mirrors sshd_reclaim/sshd_confirm in the Bash twin.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: sshd_shadows
short_description: Find sshd lines read before a drop-in that override its keywords
description:
  - Lists every line, in the main sshd config above its Include and in the
    drop-ins whose names sort before O(dropin), that sets one of the keywords
    in O(lines) to a value that is not the drop-in's.
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
  description: Lines to reclaim (path, line, raw, keyword).
  returned: always
  type: list
ports:
  description: Port lines read first with another port (named, never cut).
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
KEYWORD = re.compile(r"([^\s=]+)\s*=?\s*(.*)$")


def split_line(text):
    match = KEYWORD.match(text.strip())
    if not match:
        return None, None
    return match.group(1).lower(), " ".join(match.group(2).split()).lower()


def global_lines(path, stop_at_include):
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()
    except (IOError, OSError):
        return []
    found = []
    for number, raw in enumerate(lines, 1):
        low = raw.strip().lower()
        if re.match(r"match(\s|$)", low):
            break
        if stop_at_include and re.match(r"include\s", low):
            break
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
    # What sshd reads before the drop-in: the main file above its Include,
    # then the drop-ins whose names sort before it (glob order: Python's
    # sorted() is code-point order, the C collation).
    files = []
    if os.path.isfile(params["main_config"]):
        files.append((params["main_config"], True))
    names = set(
        os.path.basename(path)
        for path in glob.glob(os.path.join(params["dropin_dir"], "*.conf"))
        if os.path.isfile(path)
    )
    names.add(base)
    for name in sorted(names):
        if name == base:
            break
        files.append((os.path.join(params["dropin_dir"], name), False))

    shadows, ports = [], []
    for path, is_main in files:
        for number, raw in global_lines(path, is_main):
            keyword, value = split_line(raw)
            if keyword not in want or value in want[keyword]:
                continue
            hit = dict(path=path, line=number, raw=raw, keyword=keyword)
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
