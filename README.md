# TOBIRA (とびら / 扉) - Transparent Offload By Inspect-free Relay Agent

A VMess relay written in Rust.

TOBIRA accepts plain VMess+TCP inbound traffic, validates only the VMess Auth ID, and relays encrypted streams to upstream nodes without full payload inspection/decryption.

## Features

- 🔄 **Subscription Aggregation**: Load VMess subscriptions from multiple HTTP(S) and local file sources
- 🧩 **Dual VMess Parsing**: Supports both `vmess://base64(json)` (v2rayN) and `vmess://uuid@host:port?...` URL format
- 🛠️ **Processing Pipeline**: Filter/remove/rename/remove-emoji/override-security by node name and source
- 🔐 **Basic Auth for Subscriptions**: Optional HTTP Basic Auth with per-user output restrictions
- 🌐 **Multiple Output Views**: Expose multiple `/sub/<name>` outputs with independent host/port rewrite + pipeline
- ⚡ **Inspect-free Relay Path**: Route by Auth ID and forward bytes directly (TCP Fast Open on inbound/outbound TCP)
- 📡 **TCP + gRPC Upstream**: Relay to classic VMess TCP upstreams and VMess over TLS+gRPC upstreams (connection pool + stream reuse)
- ♻️ **Hot Reload**: Full reload by `SIGUSR1` or config-file change; periodic subscription-only refresh by timer
- 💾 **Cache Fallback**: Per-source cache fallback when subscription fetch fails
- ✅ **Safety Checks**: Duplicate UUID detection during routing table build

## Architecture

```
┌──────────────────────────┐
│ Subscription Sources     │
│ (HTTP/HTTPS or files)    │
└────────────┬─────────────┘
             │ load + parse VMess
             ▼
┌──────────────────────────┐
│ Process Pipeline         │
│ • filter/source filter   │
│ • remove/rename          │
│ • remove_emoji/security  │
└────────────┬─────────────┘
             │ build nodes + cache
             ▼
┌──────────────────────────┐
│ Validator (UUID/Auth ID) │
└────────────┬─────────────┘
             │ route by first 16 bytes
             ▼
┌──────────────────────────────┐      ┌───────────────────────────┐
│ TOBIRA Relay Inbound         │─────▶│ Upstream Relay            │
│ • VMess + TCP                │      │ • TCP (TFO)               │
│ • inspect-free forwarding    │      │ • TLS + gRPC (pooled H2)  │
└──────────────────────────────┘      └───────────────────────────┘
             │
             ▼
┌──────────────────────────┐
│ HTTP Subscription Server │
│ /sub /sub/<name> ...     │
└──────────────────────────┘
```

## Installation

### Build from Source

```bash
cd tobira
cargo build --release
```

Binary path:

```bash
./target/release/tobira
```

### Docker

```bash
cd tobira
docker build -t tobira:latest .
```

## Configuration

Create `config.toml` (see [config.example.toml](config.example.toml)).

### Configuration Sections

#### `relay`

- `listen`: relay bind address (default: `[::]`)
- `port`: relay inbound port (required)

Note: relay listener bind fields are **not** re-bound by hot reload. Changing `relay.listen`/`relay.port` requires process restart.

#### `http`

- `listen`: HTTP bind address (default: `[::]`)
- `port`: HTTP port (default: `8080`)
- `[[http.users]]`: Basic Auth users
  - `username`, `password`
  - optional `outputs = ["main", ...]` to restrict visible outputs
- `[[http.outputs]]`: named subscription outputs
  - `name`: output name for `/sub/<name>`
  - `host`, `port`: rewritten relay endpoint written into exported links
  - `sni`: optional TLS SNI for gRPC/TLS relay links
  - `skip-cert-verify`: optional TLS certificate verification skip for gRPC/TLS relay links
  - `[[http.outputs.process]]`: per-output processing pipeline

#### `subscription`

- `cache_file`: JSON cache path used as source fallback
- `update_interval`: periodic subscription refresh interval in seconds (`0` disables timer)
- `[[subscription.sources]]`: source definitions
  - `name`: source name
  - `url`: HTTP/HTTPS subscription URL
  - `path`: local subscription file path
  - relative `path` values are resolved from the directory containing `config.toml`
  - exactly one of `url` or `path` is required
  - `user_agent`: optional HTTP User-Agent for `url` sources
  - `[[subscription.sources.process]]`: per-source processing pipeline

#### Process Pipeline Fields

Each process step supports:

- `filter`: regex list matched against node name
- `filter_source`: regex list matched against source name
- `invert`: invert selection result
- `remove`: remove selected nodes
- `rename`: regex rename rules (`[[pattern, replacement], ...]`)
- `remove_emoji`: remove emoji characters from node name
- `override_security`: override VMess encryption/security field

## Usage

### Start the Service

```bash
./target/release/tobira --config config.toml
```

Short form:

```bash
./target/release/tobira -c config.toml
```

### Reload Behavior

- Full reload (re-read config + refetch subscriptions):
  - `SIGUSR1`
  - config file modify/create event
- Subscription-only reload (uses in-memory config):
  - periodic timer controlled by `subscription.update_interval`

Manual full reload:

```bash
kill -USR1 <pid>
```

`RUST_LOG` overrides `log_level` in `config.toml`.

## Subscription Endpoints

Supported endpoints:

- `GET /sub` and `GET /sub/base64`: all allowed outputs, VMess JSON link format
- `GET /sub/v2rayn`: alias of `/sub`, all allowed outputs, VMess JSON link format
- `GET /sub/standard`: all allowed outputs, VMess URL link format (`/sub/url` kept as compatibility alias)
- `GET /sub/<name>` and `GET /sub/<name>/base64`: one named output, VMess JSON link format
- `GET /sub/<name>/v2rayn`: alias of `/sub/<name>`, one named output, VMess JSON link format
- `GET /sub/<name>/standard`: one named output, VMess URL link format (`/sub/<name>/url` kept as compatibility alias)

Authentication:

- If `[[http.users]]` is configured, Basic Auth is required.
- If no users are configured, anonymous access is allowed.

Examples:

```bash
# JSON-format links (base64 envelope)
curl -u alice:s3cr3t http://127.0.0.1:8080/sub/main | base64 -d

# URL-format links (base64 envelope)
curl -u alice:s3cr3t http://127.0.0.1:8080/sub/main/standard | base64 -d
```

## Process Pipeline Examples

### Local Subscription File

```toml
[[subscription.sources]]
name = "local"
path = "subscriptions/local.txt"
```

### Remove Free Source Nodes

```toml
[[subscription.sources.process]]
filter_source = ["free_sub"]
remove = true
```

### Keep Only Premium Nodes

```toml
[[http.outputs.process]]
filter = ["(?i)premium"]
invert = true
remove = true
```

### Normalize Names and Security

```toml
[[http.outputs.process]]
remove_emoji = true
rename = [["^US\\s*", "US-"], ["^HK\\s*", "HK-"]]
override_security = "aes-128-gcm"
```

## Troubleshooting

### `duplicate UUID` on startup/reload

TOBIRA requires each upstream node UUID to be unique across all loaded sources. Remove duplicates or filter them out in process pipeline steps.

### `401 Unauthorized` on `/sub/*`

Check your Basic Auth credentials, or remove `[[http.users]]` entries to allow anonymous access.

## License

This repository is licensed under [GNU Affero General Public License v3.0 or later](./LICENSE).

SPDX-License-Identifier: [AGPL-3.0-or-later](https://spdx.org/licenses/AGPL-3.0-or-later.html)
