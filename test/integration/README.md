# Integration tests

These tests exercise the real raw-socket / pcap data path inside Linux network
namespaces, so they require **Linux + root + libpcap** and the tools `ip`,
`iptables`, `curl`, and `python3`. They are not run by `go test`; invoke them
directly.

## `multiclient.sh` — one server, many clients

Proves that a **single** `paqet` server serves **multiple** clients
concurrently, refuting the assumption that the architecture is one-to-one.

It builds a four-namespace topology that mirrors a real internet gateway — the
server sees one upstream gateway MAC, while two clients on separate subnets
reach it through an L3 router namespace:

```
pq-c1 (10.0.1.2) --veth-- 10.0.1.1 \
                                     pq-rt (router) --veth-- 10.0.3.1 -- pq-srv (10.0.3.2) -- target :8080
pq-c2 (10.0.2.2) --veth-- 10.0.2.1 /
```

Each client runs a SOCKS5 proxy; the harness fires concurrent HTTP requests
through both proxies to an echo target behind the server and verifies every
response, then asserts the server accepted two distinct client sessions.

```bash
sudo ./test/integration/multiclient.sh
# Env: PAQET=/path/to/prebuilt/paqet   REQS=20
# Exit: 0 = PASS, 1 = FAIL, 2 = SKIPPED (unmet requirements)
```

Why it works: the KCP listener (`kcp.ServeConn`) demuxes peers by source
IP:port, and the server's accept loop spawns a handler per session — so clients
with distinct source addresses get independent sessions. See the caveats in the
project README ("Serving multiple clients") for the limits of this model.
