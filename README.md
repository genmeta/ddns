# DDNS

`ddns` provides DNS discovery and resolver support for DHTTP applications. It is a
single Rust package: the historical `ddns-core`, `gmdns`, `ddns`, and
`ddns-server` crate boundaries now live as modules and feature-gated targets in
one published Cargo package named `dyns`, with a library target kept as `ddns`
for source compatibility.

## Crate layout

| Module / target | Role |
| --- | --- |
| `ddns::core` | DNS packet parser, resource-record types, endpoint `E` record encoding, and HTTP multi-record response wire format. |
| `ddns::mdns` | RFC 6762 multicast DNS transport, LAN publisher, and LAN resolver support. |
| `ddns::resolvers` | Resolver chain plus optional System, mDNS, DNS-over-H3, and DNS-over-HTTP resolvers. |
| `ddns::publisher` | Feature-gated endpoint record signing and publishing loop helpers for DHTTP endpoints. |
| `ddns-server` | DNS-over-H3 publish/lookup server binary, enabled by the `server` feature. |

`ddns` is endpoint-facing support code for the DHTTP ecosystem. Applications
normally reach it through the `dhttp` endpoint facade; lower-level consumers can
depend on package `dyns` directly (typically renamed locally to `ddns`) when
they need DNS wire types, resolver composition, mDNS, or the DNS-over-H3 server.

```toml
ddns = { package = "dyns", version = "0.3.0" }
```

## Features

All optional integrations are feature-gated; the default feature set is empty.

| Feature | Enables |
| --- | --- |
| `h3x-resolver` | DNS-over-H3 resolver and publisher using `h3x`/`dquic`. |
| `mdns-resolver` | mDNS resolver integration backed by an existing `h3x::dquic::Network`. |
| `http-resolver` | DNS-over-HTTP resolver/publisher using `reqwest` and native roots. |
| `server` | `ddns-server`, Redis storage support, TOML config parsing, and tracing setup. |

## Bootstrap constants

`build.rs` generates the resolver defaults exposed from `ddns::resolvers`:

| Environment variable | Public constant | Fallback when unset |
| --- | --- | --- |
| `DHTTP_H3_DNS_SERVER` | `DHTTP_H3_DNS_SERVER` | `https://dhttp.example.net` |
| `DHTTP_HTTP_DNS_SERVER` | `DHTTP_HTTP_DNS_SERVER` | `https://dhttp.example.net` |
| `DHTTP_MDNS_SERVICE` | `DHTTP_MDNS_SERVICE` | `dhttp.example.net` |

The fallbacks are docs/build placeholders, not operational defaults. Real
endpoint, server, and E2E runs should set the DHTTP bootstrap environment before
building.

## Quick start

### Resolver chain

`Resolvers` queries all configured resolvers and streams endpoint addresses from
successful backends. System DNS is always available; mDNS, H3, and HTTP builders
appear behind their features.

```rust
use ddns::resolvers::Resolvers;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), ddns::resolvers::DnsErrors> {
    let resolvers = Resolvers::builder().system().build();
    let mut endpoints = resolvers.lookup("demo.example.dhttp.net").await?;

    while let Some((source, endpoint)) = endpoints.next().await {
        println!("{source:?}: {endpoint}");
    }

    Ok(())
}
```

### mDNS discovery

```rust
use ddns::{mdns::service::Mdns, resolvers::DHTTP_MDNS_SERVICE};
use futures::StreamExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let mdns = Mdns::new(
        DHTTP_MDNS_SERVICE,
        std::net::Ipv4Addr::LOCALHOST.into(),
        "lo0",
    )?;
    let mut discoveries = mdns.discover();

    while let Some((source, packet)) = discoveries.next().await {
        println!("received packet from {source}: {packet}");
    }

    Ok(())
}
```

Runnable examples live in `examples/`:

```bash
cargo run --example mdns_discover -- --ip 127.0.0.1 --device lo0
cargo run --example mdns_query -- --ip 192.168.5.156 --device en0
```

### DNS-over-H3 examples

```bash
cargo run --example query --features h3x-resolver -- \
  --server-ca /path/to/root.crt \
  --host nat.genmeta.net

cargo run --example publish --features h3x-resolver -- \
  --server-ca /path/to/root.crt \
  --client-name demo.example.dhttp.net \
  --client-cert /path/to/demo.example.dhttp.net.pem \
  --client-key /path/to/demo.example.dhttp.net.key \
  --host demo.example.dhttp.net \
  --addr 192.168.1.100:8080,192.168.1.101:8080
```

See [`examples/README.md`](examples/README.md) for the example CLI parameters
and response decoding notes.

## DNS-over-H3 server

Start the server with the `server` feature:

```bash
cargo run --bin ddns-server --features server -- --config server.toml
```

When the configured TLS certificate includes its issuer certificate, `ddns-server`
now pulls its own stapled OCSP response from cert-server's public `POST /ocsp`
responder during startup and refreshes it every 2h55m. If the PEM only contains
the leaf certificate, set `ocsp_issuer_cert` in [server.toml](server.toml). You
can override the responder origin with `ocsp_responder_base_url`; by default it
uses `https://license.genmeta.net`.

The server can optionally enable GEO-aware lookup ordering with local MaxMind
GeoLite2 City and ASN databases. When both `geoip_city_db` and `geoip_asn_db`
are configured, lookups prefer same-country and same-ASN endpoints first, then
fall back to address family, endpoint load, and city-distance tie-breaking for
sufficiently accurate records.

For AWS deployments, keep QUIC/TLS/mTLS end-to-end in the backend, point
`redis_write_url` at the primary Redis endpoint, `redis_read_url` at a replica,
and set `host_allowlist` to the suffixes you actually serve. See
[docs/aws-deployment.md](docs/aws-deployment.md).

To update those databases on a server, use [scripts/update-geolite-mmdb.sh](scripts/update-geolite-mmdb.sh).
It wraps `geoipupdate` and downloads both `GeoLite2-City.mmdb` and
`GeoLite2-ASN.mmdb` into one directory:

```bash
MAXMIND_ACCOUNT_ID=12345 \
MAXMIND_LICENSE_KEY=your_license_key \
./scripts/update-geolite-mmdb.sh /etc/ddns
```

For detailed parameters and HTTP packet structures, see [examples/README.md](examples/README.md).

The server exposes two HTTP/3 routes:

| Route | Meaning |
| --- | --- |
| `POST /publish?host=<name>` | Publish a DNS packet for `host`. Client mTLS is required. |
| `GET /lookup?host=<name>[&limit=N]` | Look up active records for `host`; `limit` caps newest-first dynamic records. |

Lookup responses use header `x-record-format: multi` and the binary body from
`ddns::core::wire::MultiResponse`:

```text
u32 count
repeated count times:
  u32 dns_len | dns packet bytes | u32 cert_len | DER publisher certificate bytes
```

Server configuration lives in `server.toml`:

- storage is in-memory by default, or Redis when `redis = "redis://..."` is set;
- `ttl_secs` controls dynamic record expiry;
- `require_signature` controls signed endpoint-record enforcement for Standard
  domains;
- `domain_policies` are matched in order, with unlisted domains using the
  Standard policy;
- `seed_records` add static bootstrap endpoints to lookup results.

Domain policies:

| Policy | Behavior |
| --- | --- |
| `standard` | Client certificate DNS SAN must match the published host; signed `E` records are required when `require_signature = true`; each certificate fingerprint owns one active record for the host. |
| `open_multi` | Any authenticated client certificate may publish; signature checks are skipped; multiple certificate fingerprints can coexist and lookup returns newest-first records. |

Public DHTTP identity hostnames should use the canonical `DhttpName::SUFFIX`
(`.dhttp.net`). Infrastructure names such as `nat.genmeta.net` can remain under
Genmeta infrastructure domains.

## Endpoint `E` records

Custom DNS record type `E` (`QTYPE = 266`) carries DHTTP endpoint addresses. The
current wire format is:

```text
flags(u8)
[sequence(varint) if CLUSTERED]
primary address: port(u16) + IPv4/IPv6 bytes
[agent address if NAT]
[load(f32) if LOAD]
[signature: scheme(u16) + len(varint) + bytes if SIGNED]
```

Flag bits:

| Bit mask | Name | Meaning |
| --- | --- | --- |
| `0x80` | `FAMILY` | `0` = IPv4, `1` = IPv6. |
| `0x40` | `MAIN` | Primary endpoint for the name. |
| `0x20` | `CLUSTERED` | Sequence number is present; multiple publishers share the name. |
| `0x10` | `NAT` | Agent address is present for NAT traversal. |
| `0x08` | `LOAD` | One-minute load value is present. |
| `0x01` | `SIGNED` | Signature with explicit TLS signature scheme is present. |

For DHTTP endpoint publishing, `MAIN` and `sequence` are derived from the
publisher certificate's DHTTP subject key identifier. Operators do not choose
these fields manually: `primary` certificates publish `MAIN = true`,
`secondary` certificates publish `MAIN = false`, and the certificate-chain
sequence becomes the normalized endpoint-record sequence. An omitted sequence
field means sequence `0`.

Signed records encode the signature scheme in the record; the no-scheme signed
format is not accepted. Legacy unsigned fixed-length endpoint address records are
still parsed by length for address-only compatibility.

## Project structure

```text
src/core.rs                  DNS core module root
src/core/parser/             DNS packet, name, question, record, varint, and signature parsers
src/core/parser/record/      A/AAAA/SRV/TXT/PTR/CNAME/E record parsing and encoding
src/core/wire.rs             HTTP multi-record response wire format
src/mdns.rs                  mDNS module root
src/mdns/protocol.rs         UDP multicast socket and packet routing
src/mdns/service.rs          High-level mDNS service API
src/mdns/resolvers/          mDNS resolver integration
src/resolvers.rs             Resolver chain and resolver defaults
src/resolvers/h3.rs          DNS-over-H3 resolver/publisher
src/resolvers/http.rs        DNS-over-HTTP resolver/publisher
src/resolvers/deferred.rs    Deferred resolver initialization helper
src/publisher.rs             Endpoint record signer and publication loop
src/publisher/               Address selection, publish dispatch, packet signing
src/bin/ddns-server/         DNS-over-H3 server implementation
examples/                    mDNS and DNS-over-H3 example programs
server.toml                  Example server configuration
```

