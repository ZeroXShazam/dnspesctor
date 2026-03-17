# dnspector

**TCP-over-DNS tunnel**: the client listens on TCP and tunnels traffic via DNS TXT queries; the server runs a DNS server and forwards streams to a TCP destination. Useful for bypassing restrictive networks where only DNS (UDP) is allowed.

*(Binary name: `rust-dns`.)*

---

## One-liner install

**Requires:** [Rust](https://rustup.rs/) (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

From a **clone** of this repo (recommended):

```bash
git clone https://github.com/ZeroXShazam/dnspesctor.git && cd dnspesctor && ./scripts/install.sh
```

Binary will be at `0.x.x/rust-dns` (e.g. `0.1.3/rust-dns`). Optionally install to your PATH:

```bash
./scripts/install.sh --install
# Binary in ~/.local/bin/rust-dns (add to PATH if needed)
```

**Standalone one-liner** (no clone; fetches install script from the repo):

```bash
bash -c "$(curl -sSfL https://raw.githubusercontent.com/ZeroXShazam/dnspesctor/main/scripts/install.sh)"
```

---

## Setup overview

1. **Server** (VPS or machine with a public IP): run `rust-dns server`, allow UDP in the firewall, optionally run iptables script.
2. **Client** (laptop or restricted network): run `rust-dns client` pointing at the server; connect apps to the client’s listen address.

You can use the server’s **IP** or a **hostname** (e.g. `dns.example.com`) for the client’s `-d`; hostnames are resolved before starting the tunnel.

---

## Server setup

### 1. Run the server

Port **53** often needs root and can conflict with system DNS. Using **5353** is simpler and works from anywhere:

```bash
sudo ./0.1.3/rust-dns server -b 0.0.0.0:5353 -d t.decycle.io -t 127.0.0.1:8080
```

- `-b 0.0.0.0:5353` — listen on UDP 5353 (no root needed if you use 5353).
- `-d t.decycle.io` — tunnel domain (same as client’s `-m`).
- `-t 127.0.0.1:8080` — forward tunneled TCP to this address (e.g. a local HTTP proxy or `nc -l -p 8080` for testing).

### 2. Firewall (iptables)

Allow UDP 5353 (and optionally 53) and SSH. From the repo on the server:

```bash
sudo ./scripts/iptables-server.sh
```

Or manually:

```bash
sudo iptables -A INPUT -p udp --dport 5353 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Allow established/related
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Persist rules (Debian/Ubuntu): `sudo iptables-save | sudo tee /etc/iptables/rules.v4`

### 3. Something on the destination port

Tunneled traffic is sent to `-t 127.0.0.1:8080`. Start a listener there for testing, e.g.:

```bash
nc -l -p 8080
```

---

## Client setup

### 1. Run the client

Use the **server IP** or **hostname** (e.g. `dns.decycle.io`), and the **same domain** as the server’s `-d`. Use `--dns-port 5353` if the server listens on 5353:

```bash
./0.1.3/rust-dns client -l 127.0.0.1:1080 -d dns.decycle.io -m t.decycle.io --dns-port 5353
```

- `-l 127.0.0.1:1080` — local TCP address for apps to connect to (e.g. SOCKS or raw TCP).
- `-d dns.decycle.io` — server hostname or IP (resolved at startup).
- `-m t.decycle.io` — tunnel domain (must match server).
- `--dns-port 5353` — server’s UDP port.

### 2. Use the tunnel

Connect to `127.0.0.1:1080`. Example with netcat:

```bash
nc 127.0.0.1 1080
```

Whatever you type is sent over DNS to the server and then to `127.0.0.1:8080` (or whatever you set with `-t`).

---

## Check connectivity (probe)

Before using the client, verify the server is reachable:

```bash
./0.1.3/rust-dns probe -d dns.decycle.io -m t.decycle.io --dns-port 5353
```

- **`probe: OK — tunnel server responded`** — ready to use the client.
- **`NXDomain`** — something else is answering on that port, or the server isn’t running.
- **`timeout`** — port closed or filtered (firewall / provider).

---

## DNS records (optional)

You **don’t** need any records for the tunnel domain (`t.decycle.io`). It’s only a label shared between client and server.

To use a **hostname** for the server (e.g. `dns.decycle.io`), add an A record:

| Type | Name | Value        |
|------|------|--------------|
| A    | dns  | \<server IP\> |

Then use `-d dns.decycle.io` on the client and in the probe.

---

## Commands reference

| Command   | Description |
|----------|-------------|
| `server` | Run DNS tunnel server (UDP). |
| `client` | Run tunnel client (TCP listen → tunnel over DNS). |
| `probe`  | Send one TXT query to the server; check reachability. |
| `local-test` | Run server + client locally and verify data (no root). |

**Server:** `rust-dns server -b <bind> -d <domain> -t <destination>`  
**Client:** `rust-dns client -l <listen> -d <server_ip_or_host> -m <domain> [--dns-port 5353]`  
**Probe:** `rust-dns probe -d <server_ip_or_host> -m <domain> [--dns-port 5353]`

---

## Local test (no server needed)

```bash
cargo run --release -- local-test
```

Runs server on 127.0.0.1:5353, client on 127.0.0.1:1080, sends a test payload. Expect: `local-test OK: data reached destination`.

---

## Build only (no install script)

```bash
cargo build --release
# Binary: target/release/rust-dns
```

Or build and copy into version folder:

```bash
./scripts/build-release.sh
# Binary: 0.1.3/rust-dns (version from Cargo.toml)
```

---

## License

See repository for license information.
