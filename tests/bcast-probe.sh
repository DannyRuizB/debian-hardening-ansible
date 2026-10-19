#!/usr/bin/env bash
# =============================================================================
# Behavioural probe for sysctl_hardening (icmp_echo_ignore_broadcasts): does the node
# ANSWER a ping sent to its network's broadcast address?
#
#   ./bcast-probe.sh [NODE_CONTAINER]   (default dh-test-node)
#
# A host that answers broadcast pings is a smurf amplifier: one request with a
# forged source, sent to the broadcast address, and every such host on the
# segment fires a reply at the victim. A throwaway neighbour joins the node's
# Docker network and sends 5 echo requests to the broadcast address.
#
# The neighbour's own ping count proves nothing here - measured: the node's
# replies never reach it, because the host's bridge netfilter
# (bridge-nf-call-iptables=1) drops a reply conntrack cannot match to a
# request sent to the broadcast address. So the count is read where the reply
# is born, in the node's own network namespace (/proc/net/snmp), before and
# after:
#   InEchos     - echo requests that reached the node's ICMP layer. Counted
#                 BEFORE the broadcast check, so it proves the requests
#                 arrived: a firewall dropping them would leave it flat, and
#                 "no reply" would then prove nothing (SETUP-FAILED);
#   OutEchoReps - echo replies the node's kernel built.
# Measured (two alpine nodes on one network, 5 requests): InEchos +5 on both,
# OutEchoReps +5 at icmp_echo_ignore_broadcasts=0 and +0 at 1 - and the node
# at 1 still answered a direct ping.
#
# Prints one line: RESULT=<ANSWERS|IGNORES|SETUP-FAILED> IN=<n> OUT=<n>
# =============================================================================
set -uo pipefail
NODE="${1:-dh-test-node}"
NB="bcast-probe-$$"

icmp() {  # $1 = a counter of the Icmp: lines in the node's /proc/net/snmp
  docker exec "$NODE" cat /proc/net/snmp 2>/dev/null \
    | awk -v want="$1" '$1 == "Icmp:" { if (!h) { for (i = 1; i <= NF; i++) n[i] = $i; h = 1 } else { for (i = 1; i <= NF; i++) if (n[i] == want) print $i } }'
}

net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$NODE" 2>/dev/null | awk '{print $1}')
[ -n "$net" ] || { echo "RESULT=SETUP-FAILED IN=0 OUT=0 (no network for $NODE)"; exit 0; }
trap 'docker rm -f "$NB" >/dev/null 2>&1' EXIT
docker run -d --name "$NB" --network "$net" alpine:3 sleep 120 >/dev/null 2>&1 \
  || { echo "RESULT=SETUP-FAILED IN=0 OUT=0 (neighbour did not start)"; exit 0; }
docker exec "$NB" sh -c 'apk add -q iputils-ping iproute2 >/dev/null 2>&1 && ping -V >/dev/null 2>&1' \
  || { echo "RESULT=SETUP-FAILED IN=0 OUT=0 (neighbour tools)"; exit 0; }
brd=$(docker exec "$NB" ip -o -4 addr show dev eth0 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "brd") print $(i + 1)}')
[ -n "$brd" ] || { echo "RESULT=SETUP-FAILED IN=0 OUT=0 (no broadcast address on $net)"; exit 0; }

in0=$(icmp InEchos)
out0=$(icmp OutEchoReps)
docker exec "$NB" ping -b -c 5 -i 0.2 -W 1 "$brd" >/dev/null 2>&1
in1=$(icmp InEchos)
out1=$(icmp OutEchoReps)
if [ -z "$in0" ] || [ -z "$in1" ] || [ -z "$out0" ] || [ -z "$out1" ]; then
  echo "RESULT=SETUP-FAILED IN=0 OUT=0 (could not read the node's ICMP counters)"; exit 0
fi
din=$((in1 - in0))
dout=$((out1 - out0))
if [ "$dout" -gt 0 ]; then result=ANSWERS
elif [ "$din" -ge 5 ]; then result=IGNORES
else result=SETUP-FAILED; fi
echo "RESULT=$result IN=$din OUT=$dout"
