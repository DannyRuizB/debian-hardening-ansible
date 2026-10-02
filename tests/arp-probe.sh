#!/usr/bin/env bash
# =============================================================================
# Behavioural probe for the arp_flux role (step 54 in the Bash twin): does a box with two networks give
# its address on one of them away on the OTHER?
#
#   ./arp-probe.sh [NODE_CONTAINER]   (default dh-test-node)
#
# A throwaway second Docker network is attached to the node (its eth1), and a
# throwaway neighbour on the node's FIRST network asks two things:
#   arp_ignore   - `arping -I eth0 <node's eth1 address>`: does the node answer,
#                  on network A, for the address it only has on network B?
#   arp_announce - the node pings the neighbour FROM its eth1 address: which
#                  sender IP does its ARP request on network A carry?
# Measured on debian:13 / alpine netns pairs: with Linux's defaults (0/0) the
# node answers for its eth1 address and its request says "tell <eth1 address>"
# on network A; with arp_ignore=1 / arp_announce=2 it stays silent and says
# "tell <eth0 address>". ARP is below netfilter: ufw plays no part.
# The second network and the neighbour are removed whatever happens.
#
# Prints: RESULT=<LEAKS|CLEAN|SETUP-FAILED> REPLIES=<n> TELL=<sender ip>
# (LEAKS when either leak shows). The neighbour installs its tools before
# anything else.
# =============================================================================
set -uo pipefail
NODE="${1:-dh-test-node}"
NET2="arp-probe-net-$$"
ATK="arp-probe-$$"
SUB2="172.31.$(( 100 + $$ % 100 )).0/24"

cleanup() {
  docker rm -f "$ATK" >/dev/null 2>&1
  docker network disconnect -f "$NET2" "$NODE" >/dev/null 2>&1
  docker network rm "$NET2" >/dev/null 2>&1
}
trap cleanup EXIT

net1=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$NODE" 2>/dev/null | awk '{print $1}')
ip1=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net1\").IPAddress}}" "$NODE" 2>/dev/null)
[ -n "$net1" ] && [ -n "$ip1" ] || { echo "RESULT=SETUP-FAILED REPLIES=0 TELL=- (no network for $NODE)"; exit 0; }
docker network create --subnet "$SUB2" "$NET2" >/dev/null 2>&1 \
  && docker network connect "$NET2" "$NODE" >/dev/null 2>&1 \
  || { echo "RESULT=SETUP-FAILED REPLIES=0 TELL=- (second network)"; exit 0; }
ip2=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET2\").IPAddress}}" "$NODE")
docker run -d --name "$ATK" --network "$net1" --privileged alpine:3 sleep 120 >/dev/null 2>&1 \
  && docker exec "$ATK" sh -c 'apk add -q iputils-arping tcpdump iproute2 >/dev/null 2>&1 && command -v arping >/dev/null && command -v tcpdump >/dev/null' \
  || { echo "RESULT=SETUP-FAILED REPLIES=0 TELL=- (neighbour tools)"; exit 0; }
atk_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net1\").IPAddress}}" "$ATK")

replies=$(docker exec "$ATK" sh -c "arping -c 2 -w 3 -I eth0 $ip2 2>/dev/null" | grep -c 'reply from')
docker exec "$NODE" ip neigh flush dev eth0 >/dev/null 2>&1
# Only requests the NODE sends (sender = one of its two addresses): the Docker
# gateway ARPs on the same segment and was once captured instead.
docker exec -d "$ATK" sh -c "timeout 8 tcpdump -lni eth0 -c 1 'arp and arp[6:2] == 1 and (arp src host $ip1 or arp src host $ip2)' > /tmp/arp.txt 2>/dev/null"
sleep 1
# A helper sharing the node's network namespace (same interfaces, same
# sysctls - what is being measured) sends one UDP datagram to 123 from the
# eth1 address: NTP is on step 49's egress allowlist, so the packet clears
# netfilter OUTPUT and the kernel has to ARP for the neighbour (a ping would
# be rejected by the outbound policy before any ARP is sent).
docker run --rm --network "container:$NODE" alpine:3 sh -c \
  "apk add -q socat >/dev/null 2>&1 && echo arp-probe | socat -u - UDP4-SENDTO:$atk_ip:123,bind=$ip2" >/dev/null 2>&1
sleep 2
tell=$(docker exec "$ATK" cat /tmp/arp.txt 2>/dev/null | sed -n 's/.* tell \([0-9.]*\).*/\1/p' | head -1)
[ -n "$tell" ] || tell="-"
if [ "$replies" -gt 0 ] || [ "$tell" = "$ip2" ]; then result=LEAKS
elif [ "$tell" = "$ip1" ]; then result=CLEAN
else result=SETUP-FAILED; fi
echo "RESULT=$result REPLIES=$replies TELL=$tell (eth0 $ip1, eth1 $ip2)"
