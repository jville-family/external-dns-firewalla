# external-dns Firewalla

Webhook provider that syncs [external-dns](https://github.com/kubernetes-sigs/external-dns) records into a [Firewalla](https://firewalla.com/) router's local `dnsmasq` configuration.

```
external-dns ──► Webhook Proxy (K8s) ──HMAC──► Listener (Firewalla) ──► dnsmasq / firerouter_dns
```

Two Go binaries, zero third-party dependencies:

| Component | Where it runs | Role |
|-----------|---------------|------|
| **proxy** | Kubernetes (Helm) | Implements the external-dns webhook provider API |
| **listener** | Firewalla (systemd) | Owns `state.json`, renders dnsmasq config, restarts DNS |

## Architecture highlights

- **Serial queue** on the listener (cap 8) so read and write never race; full queue returns `503` + `Retry-After`.
- **No-op gate**: identical payloads skip disk writes and `firerouter_dns` restarts (flash-wear protection).
- **Atomic writes** of both `state.json` and the dnsmasq conf via temp file + `fsync` + rename.
- **HMAC-SHA256** auth with a 10-second replay window between proxy and listener.
- **Least privilege**: the listener runs as user `pi` and may only `sudo systemctl {restart,stop,start} firerouter_dns` via a drop-in sudoers rule.
- **Firmware survival**: state, unit, and sudoers templates live under `/home/pi/.firewalla/`; a `post_main.d` bootstrapper reinstalls them into `/etc` after upgrades wipe it.

## Prerequisites

- Firewalla with SSH access (Gold / Gold Pro / Gold SE / Purple)
- Kubernetes cluster with external-dns
- A shared HMAC secret
- Domains you will manage (e.g. `app.lan`)

## Install the Firewalla Listener

### 1. Create directories and config

```bash
ssh pi@<firewalla>

mkdir -p /home/pi/.firewalla/k8s-external-dns
mkdir -p /home/pi/.firewalla/config/dnsmasq_local
mkdir -p /home/pi/.firewalla/config/post_main.d
```

Copy `deploy/firewalla/config.env.example` to `/home/pi/.firewalla/k8s-external-dns/config.env` and edit:

```bash
HMAC_SECRET=<long-random-secret>
ALLOWED_DOMAINS=app.lan,k8s.local
LISTEN_ADDR=0.0.0.0          # NOT the default 127.0.0.1 — cluster must reach this
LISTEN_PORT=10053
LOG_LEVEL=warn
```

> **Note:** The default `LISTEN_ADDR=127.0.0.1` binds loopback only. You must set it to the Firewalla LAN address (or `0.0.0.0`) for the Kubernetes proxy to connect.

### 2. Install the binary, sudoers rule, and systemd unit

Download the matching release asset (`listener-linux-arm64` for Purple / Gold SE, `listener-linux-amd64` for Gold / Gold Pro):

```bash
install -m 0755 listener-linux-arm64 /home/pi/.firewalla/k8s-external-dns/listener

# Durable copies (survive firmware upgrades)
cp k8s-external-dns-listener.service /home/pi/.firewalla/k8s-external-dns/
mkdir -p /home/pi/.firewalla/k8s-external-dns/sudoers.d
cp sudoers.d/k8s-external-dns /home/pi/.firewalla/k8s-external-dns/sudoers.d/

# Live /etc copies
install -m 0440 /home/pi/.firewalla/k8s-external-dns/sudoers.d/k8s-external-dns /etc/sudoers.d/k8s-external-dns
visudo -cf /etc/sudoers.d/k8s-external-dns   # must report OK
cp /home/pi/.firewalla/k8s-external-dns/k8s-external-dns-listener.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now k8s-external-dns-listener.service
```

The service runs as **`User=pi`**. Reloads go through `sudo` and are limited to:

`systemctl restart|stop|start firerouter_dns` (absolute paths `/usr/bin/systemctl` and `/bin/systemctl`).

### 3. Install the firmware-survival bootstrapper

```bash
cp start-k8s-dns.sh /home/pi/.firewalla/config/post_main.d/start-k8s-dns.sh
chmod +x /home/pi/.firewalla/config/post_main.d/start-k8s-dns.sh
```

**You must run `chmod +x`** on that script so Firewalla executes it on every boot. After a firmware upgrade wipes `/etc`, the script reinstalls the sudoers drop-in and systemd unit from `/home/pi/.firewalla/k8s-external-dns/` and starts the service.

### 4. Allow traffic from the Kubernetes subnet

> **Warning:** You **must** use the Firewalla App to create a **Local Network** rule that allows traffic from your Kubernetes node/pod subnet to the Firewalla on `LISTEN_PORT` (default `10053`). Without this rule the webhook proxy cannot reach the listener and readiness probes will fail.

### 5. Verify

```bash
curl -s http://127.0.0.1:10053/health
systemctl status k8s-external-dns-listener
```

## Deploy the Webhook Proxy (Helm / Flux)

### Helm

```bash
helm install external-dns-firewalla oci://ghcr.io/jville-family/external-dns-firewalla \
  --namespace external-dns --create-namespace \
  --set secret.hmacSecret="<same-secret-as-listener>" \
  --set config.listenerURL="http://<firewalla-lan-ip>:10053" \
  --set config.allowedDomains="app.lan,k8s.local"
```

Point external-dns at the proxy:

```
--provider=webhook
--webhook-provider-url=http://external-dns-firewalla.external-dns.svc:8888
```

(Sidecar-on-localhost is also supported; adjust the Service / URL accordingly.)

### Flux CD

See [`deploy/flux/helmrelease.yaml`](deploy/flux/helmrelease.yaml). Create a Secret named `external-dns-firewalla-hmac` with key `HMAC_SECRET`, then apply the `HelmRepository` + `HelmRelease`.

## DNS record mapping

| Type | dnsmasq directive |
|------|-------------------|
| A / AAAA | `host-record=name,ipv4,ipv6` (exact match; A+AAAA for the same name merge onto one line) |
| CNAME | `cname=alias,target[,ttl]` |
| TXT | `txt-record=name,"value"` (quoted; values &gt;255 chars are chunked) |
| SRV | `srv-host=name,target,port,priority,weight` |

### Known limitations

- **CNAME targets must already be known to dnsmasq** (from `host-record`, hosts files, or DHCP leases). A CNAME pointing at an upstream-only name will not resolve — this is a dnsmasq restriction, not a bug in this project.
- Only `A`, `AAAA`, `CNAME`, `TXT`, and `SRV` are accepted; other types are dropped.
- Domain filtering uses strict suffix matching with a leading-dot boundary (`app.lan` matches `plex.app.lan` but not `badapp.lan`).

## Paths on Firewalla (survive firmware upgrades)

| Path | Purpose |
|------|---------|
| `/home/pi/.firewalla/k8s-external-dns/state.json` | Managed record state |
| `/home/pi/.firewalla/k8s-external-dns/config.env` | Listener environment |
| `/home/pi/.firewalla/k8s-external-dns/listener` | Binary |
| `/home/pi/.firewalla/k8s-external-dns/k8s-external-dns-listener.service` | Unit template |
| `/home/pi/.firewalla/k8s-external-dns/sudoers.d/k8s-external-dns` | Sudoers template |
| `/etc/sudoers.d/k8s-external-dns` | Live sudoers (restored on boot) |
| `/home/pi/.firewalla/config/dnsmasq_local/k8s-external-dns.conf` | Generated dnsmasq config |
| `/home/pi/.firewalla/config/post_main.d/start-k8s-dns.sh` | Boot bootstrapper |

## Development

```bash
make test          # go test -race -cover ./...
make vet
make build         # bin/listener and bin/proxy
make helm-lint
```

TDD: each package under `internal/` has tests that were written before the implementation.

## Releases

Tagging `v*` triggers:

1. Multi-arch proxy image → `ghcr.io/<owner>/external-dns-firewalla`
2. Helm chart OCI push → `oci://ghcr.io/<owner>/external-dns-firewalla`
3. Cross-compiled listener binaries (`linux/arm64`, `linux/amd64`, `-ldflags="-s -w"`) attached to the GitHub Release

## License

See [LICENSE](LICENSE).
