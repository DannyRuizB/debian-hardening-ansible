#!/usr/bin/env bash
# =============================================================================
# Behavioural probe for the loopback_isolation role (step 53 in the Bash twin): can a NEIGHBOUR on the
# node's network reach a service the node only has on 127.0.0.1?
#
#   ./loopback-probe.sh [NODE_CONTAINER]   (default dh-test-node)
#
# A throwaway attacker container joins the node's Docker network, deletes its
# own 127.0.0.0/8 routes and routes 127.0.0.1 via the node - what any host on
# the same L2 can do. It then opens TCP connections to 127.0.0.1:22 (sshd
# listens there too, and port 22 is one ufw allows, so the firewall's default
# deny is NOT what decides) and counts the SYN-ACKs that come back FROM
# 127.0.0.1. Measured: with route_localnet=1 on the node and no loopback rule
# the node answers; with route_localnet=0, or with the role's DROP, it does
# not. The attacker's own kernel discards those SYN-ACKs (source 127.0.0.1 on
# eth0), so no session ever opens - the SYN-ACK is the proof the node
# accepted the packet for its loopback service.
#
# Prints one line: RESULT=<ALLOWED|DENIED|SETUP-FAILED> SYNACK=<n> DROPPED=<n|NA>
# DROPPED is the packet counter of the node's `! -i lo -d 127.0.0.0/8 -j DROP`
# rule in ufw-before-input (NA when there is no such rule): a DENIED with a
# rising counter is the rule doing it, not a probe that never arrived.
# The attacker installs its tools BEFORE breaking its 127 routes: Docker's
# embedded DNS lives on 127.0.0.11, and the first try of this probe lost it.
# =============================================================================
set -uo pipefail
NODE="${1:-dh-test-node}"
ATK="lo-probe-$$"

drop_count() {
  docker exec "$NODE" iptables -L ufw-before-input -v -n -x 2>/dev/null \
    | awk '$3 == "DROP" && $(NF) == "127.0.0.0/8" && $(NF-1) == "0.0.0.0/0" {print $1; f=1} END {if (!f) print "NA"}'
}

ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$NODE" 2>/dev/null | awk '{print $1}')
net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$NODE" 2>/dev/null | awk '{print $1}')
if [ -z "$ip" ] || [ -z "$net" ]; then
  echo "RESULT=SETUP-FAILED SYNACK=0 DROPPED=NA (no IP/network for $NODE)"; exit 0
fi
trap 'docker rm -f "$ATK" >/dev/null 2>&1' EXIT
docker run -d --name "$ATK" --network "$net" --privileged alpine:3 sleep 120 >/dev/null 2>&1 \
  || { echo "RESULT=SETUP-FAILED SYNACK=0 DROPPED=NA (attacker did not start)"; exit 0; }
docker exec "$ATK" sh -c 'apk add -q iproute2 tcpdump >/dev/null 2>&1 && command -v tcpdump >/dev/null' \
  || { echo "RESULT=SETUP-FAILED SYNACK=0 DROPPED=NA (attacker tools)"; exit 0; }
docker exec "$ATK" sh -c "sysctl -qw net.ipv4.conf.all.route_localnet=1 net.ipv4.conf.eth0.route_localnet=1 \
    net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth0.rp_filter=0 &&
  ip route del local 127.0.0.0/8 dev lo table local &&
  ip route del local 127.0.0.1 dev lo table local &&
  ip route add 127.0.0.1/32 via $ip dev eth0 &&
  ip route get 127.0.0.1 | grep -q 'via $ip'" >/dev/null 2>&1 \
  || { echo "RESULT=SETUP-FAILED SYNACK=0 DROPPED=NA (attacker routing)"; exit 0; }

before=$(drop_count)
out=$(docker exec "$ATK" sh -c '
  timeout 8 tcpdump -lni eth0 -c 1 "src host 127.0.0.1 and src port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)" 2>/dev/null &
  sleep 1
  for i in 1 2 3; do timeout 2 nc -w 1 127.0.0.1 22 </dev/null >/dev/null 2>&1; done
  wait' 2>/dev/null)
after=$(drop_count)
synack=$(grep -c '127\.0\.0\.1\.22 >' <<<"$out")
dropped="NA"
if [ "$before" != "NA" ] && [ "$after" != "NA" ]; then dropped=$((after - before)); fi
if [ "$synack" -gt 0 ]; then result=ALLOWED; else result=DENIED; fi
echo "RESULT=$result SYNACK=$synack DROPPED=$dropped"
