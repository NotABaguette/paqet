#!/usr/bin/env bash
#
# multiclient.sh - proves that a SINGLE paqet server serves MULTIPLE clients
# concurrently over the real raw-socket / pcap data path.
#
# It builds a Linux network-namespace topology that mirrors a real internet
# gateway: the server sees ONE upstream gateway MAC while N clients, each on
# their own subnet, reach it via an L3 router namespace. Each client runs a
# paqet SOCKS5 proxy; the harness drives concurrent HTTP requests through both
# proxies to a target served behind the server and verifies every response.
#
#   pq-c1 (10.0.1.2) --veth-- 10.0.1.1 \
#                                       pq-rt (router, ip_forward) --veth-- 10.0.3.1 -- pq-srv (10.0.3.2) -- target :8080
#   pq-c2 (10.0.2.2) --veth-- 10.0.2.1 /
#
# Requirements: Linux, root (raw sockets + netns), libpcap, and the tools
# ip, iptables, curl, python3. A Go toolchain is needed unless PAQET points
# at a prebuilt binary.
#
# Usage:   sudo ./test/integration/multiclient.sh
# Env:     PAQET=/path/to/paqet   REQS=20   (requests per client)
# Exit:    0 = PASS, 1 = FAIL, 2 = SKIPPED (unmet requirements)
#
set -u

PORT=9999
KEY="multiclient-integration-key"
REQS="${REQS:-20}"
WORK="$(mktemp -d /tmp/paqet-mc.XXXXXX)"
NS=(pq-rt pq-c1 pq-c2 pq-srv)

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }

skip(){ echo "SKIP: $*"; exit 2; }

# --- preflight -------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || skip "Linux only"
[ "$(id -u)" = "0" ] || skip "must run as root"
for t in ip iptables curl python3; do command -v "$t" >/dev/null || skip "missing tool: $t"; done

PAQET="${PAQET:-}"
if [ -z "$PAQET" ]; then
  command -v go >/dev/null || skip "no PAQET binary and no go toolchain"
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  PAQET="$WORK/paqet"
  echo "building paqet from $ROOT ..."
  ( cd "$ROOT" && go build -o "$PAQET" ./cmd ) || skip "build failed (libpcap-dev installed?)"
fi

cleanup(){
  for ns in "${NS[@]}"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- topology --------------------------------------------------------------
for ns in "${NS[@]}"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
mkveth(){ # leafns leafip rtif rtip
  ip link add eth0 netns "$1" type veth peer name "$3" netns pq-rt
  ip -n "$1" addr add "$2/24" dev eth0; ip -n "$1" link set eth0 up
  ip -n pq-rt addr add "$4/24" dev "$3"; ip -n pq-rt link set "$3" up
}
mkveth pq-c1  10.0.1.2 to-c1  10.0.1.1
mkveth pq-c2  10.0.2.2 to-c2  10.0.2.1
mkveth pq-srv 10.0.3.2 to-srv 10.0.3.1
ip -n pq-c1  route add default via 10.0.1.1
ip -n pq-c2  route add default via 10.0.2.1
ip -n pq-srv route add default via 10.0.3.1
ip netns exec pq-rt sysctl -wq net.ipv4.ip_forward=1

MAC_C1=$(ip -n pq-rt link show to-c1  | awk '/link\/ether/{print $2}')
MAC_C2=$(ip -n pq-rt link show to-c2  | awk '/link\/ether/{print $2}')
MAC_SR=$(ip -n pq-rt link show to-srv | awk '/link\/ether/{print $2}')

# server-side firewall rules (per README) so the kernel does not interfere
ip netns exec pq-srv iptables -t raw    -A PREROUTING -p tcp --dport $PORT -j NOTRACK
ip netns exec pq-srv iptables -t raw    -A OUTPUT     -p tcp --sport $PORT -j NOTRACK
ip netns exec pq-srv iptables -t mangle -A OUTPUT     -p tcp --sport $PORT --tcp-flags RST RST -j DROP

# --- configs ---------------------------------------------------------------
cat > "$WORK/server.yaml" <<EOF
role: "server"
log: { level: "info" }
listen: { addr: ":$PORT" }
network: { interface: "eth0", ipv4: { addr: "10.0.3.2:$PORT", router_mac: "$MAC_SR" } }
transport: { protocol: "kcp", kcp: { block: "aes", key: "$KEY" } }
EOF
mkclient(){ cat > "$1" <<EOF
role: "client"
log: { level: "info" }
socks5: [ { listen: "127.0.0.1:1080" } ]
network: { interface: "eth0", ipv4: { addr: "$2:0", router_mac: "$3" } }
server: { addr: "10.0.3.2:$PORT" }
transport: { protocol: "kcp", kcp: { block: "aes", key: "$KEY" } }
EOF
}
mkclient "$WORK/c1.yaml" 10.0.1.2 "$MAC_C1"
mkclient "$WORK/c2.yaml" 10.0.2.2 "$MAC_C2"

# --- target: echoes the request path so each client verifies its own reply --
cat > "$WORK/echo.py" <<'EOF'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=self.path.encode(); self.send_response(200)
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
ThreadingHTTPServer(("10.0.3.2",8080),H).serve_forever()
EOF

# --- run -------------------------------------------------------------------
ip netns exec pq-srv python3 "$WORK/echo.py" & ECHO=$!; sleep 0.4
ip netns exec pq-srv "$PAQET" run -c "$WORK/server.yaml" >"$WORK/server.log" 2>&1 & SRV=$!; sleep 1.5
ip netns exec pq-c1 "$PAQET" run -c "$WORK/c1.yaml" >"$WORK/c1.log" 2>&1 & CL1=$!
ip netns exec pq-c2 "$PAQET" run -c "$WORK/c2.yaml" >"$WORK/c2.log" 2>&1 & CL2=$!
sleep 5

load(){ # ns tag outfile
  local ns=$1 tag=$2 out=$3 ok=0 i r
  for i in $(seq 1 "$REQS"); do
    r=$(ip netns exec "$ns" curl -s --max-time 8 --socks5-hostname 127.0.0.1:1080 "http://10.0.3.2:8080/$tag-$i")
    [ "$r" = "/$tag-$i" ] && ok=$((ok+1))
  done
  echo "$ok" > "$out"
}
load pq-c1 c1 "$WORK/s1" & P1=$!
load pq-c2 c2 "$WORK/s2" & P2=$!
wait "$P1" "$P2"                       # wait only on the load jobs
kill "$ECHO" "$SRV" "$CL1" "$CL2" 2>/dev/null

S1=$(cat "$WORK/s1" 2>/dev/null || echo 0)
S2=$(cat "$WORK/s2" 2>/dev/null || echo 0)
SESS=$(grep -oE "accepted new connection from 10\.0\.[12]\.2:[0-9]+" "$WORK/server.log" | sort -u)
NSESS=$(printf '%s\n' "$SESS" | grep -c . || true)

echo "======================= RESULTS ======================="
echo "requests/client: $REQS"
echo "client1 correct echoes: $S1 / $REQS"
echo "client2 correct echoes: $S2 / $REQS"
echo "distinct client sessions on the single server: $NSESS"
printf '%s\n' "$SESS" | sed 's/^/   /'
echo "======================================================="

if [ "$S1" -eq "$REQS" ] && [ "$S2" -eq "$REQS" ] && [ "$NSESS" -eq 2 ]; then
  grn "VERDICT: PASS - one server served both clients ($((REQS*2))/$((REQS*2)) requests OK)"
  exit 0
else
  red "VERDICT: FAIL (c1=$S1 c2=$S2 sessions=$NSESS); logs under server.log/c1.log/c2.log"
  cat "$WORK/server.log" 2>/dev/null | tail -20
  exit 1
fi
