# DDNS

`ddns` provides DNS discovery and resolver support for DHTTP applications.
The published Cargo package is `dyns`, and the library target remains `ddns`.

`ddns` exposes backend implementations in `ddns::h3`, `ddns::http`, and `ddns::mdns`,
while `ddns::resolvers` and `ddns::publishers` act as facades for re-exports and
aggregate helper types.

```toml
ddns = { package = "dyns", version = "0.3.0" }
```

## Crate layout

| Module | Role |
| --- | --- |
| `ddns::core` | DNS packet parser, resource-record types, endpoint `E` record encoding, and HTTP multi-record response wire format. |
| `ddns::h3` | DNS-over-HTTP/3 backend implementation. |
| `ddns::http` | DNS-over-HTTP backend implementation. |
| `ddns::mdns` | RFC 6762 multicast DNS transport plus LAN resolver/publisher backend implementation. |
| `ddns::resolvers` | Resolver facade: backend re-exports, resolver chains, and `Resolvers` aggregation. |
| `ddns::publishers` | Publisher facade: backend re-exports, scoped publisher atoms, `Publishers` aggregation, and endpoint publication helpers. |

## Features

The default feature set is empty.

| Feature | Enables |
| --- | --- |
| `resolvers` | Resolver aggregation types such as `Resolvers`, `ResolversBuilder`, and `DnsScheme`. |
| `publishers` | Scoped publication helpers such as `Publisher`, `Publishers`, `PublishScope`, `EndpointPublicationLoop`, and `PublishAddresses`; backend `Publish` implementations own any required signing. |
| `dquic-network` | `h3x`/`dquic` network-backed publication helpers such as `EndpointBindingAddresses`; meaningful together with `publishers`, and also used by mDNS resolver aggregation. |
| `h3` | DNS-over-HTTP/3 backend surface (`ddns::h3`, plus `H3Resolver` / `H3Publisher` re-exports from the facades). |
| `http` | DNS-over-HTTP backend surface (`ddns::http`, plus `HttpResolver` / `HttpPublisher` re-exports from the facades). |
| `mdns` | mDNS backend surface (`ddns::mdns`, plus `MdnsResolver` / `MdnsPublisher` re-exports from the facades). |

Backend types live under the `resolvers` / `publishers` facades whenever their backend feature is enabled.
The aggregate `Resolvers` and endpoint-publication helper types are separately gated by the
`resolvers` and `publishers` features.

## Bootstrap constants

`build.rs` generates resolver defaults exposed from `ddns::resolvers`:

| Environment variable | Public constant | Fallback when unset |
| --- | --- | --- |
| `DHTTP_H3_DNS_SERVER` | `DHTTP_H3_DNS_SERVER` | `https://dhttp.example.net` |
| `DHTTP_HTTP_DNS_SERVER` | `DHTTP_HTTP_DNS_SERVER` | `https://dhttp.example.net` |
| `DHTTP_MDNS_SERVICE` | `DHTTP_MDNS_SERVICE` | `dhttp.example.net` |

The fallbacks are docs/build placeholders, not operational defaults.

## Quick start

### Resolver chain

Enable the resolver aggregation surface and build a chain explicitly:

```rust
use ddns::resolvers::Resolvers;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), ddns::resolvers::ResolversError> {
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

Runnable examples:

```bash
cargo run --example mdns_discover --features mdns -- --ip 127.0.0.1 --device lo0
cargo run --example mdns_query --features mdns -- --ip 192.168.5.156 --device en0
cargo run --example query -- --server-ca /path/to/root.crt --host nat.genmeta.net
cargo run --example publish --features h3 -- \
  --server-ca /path/to/root.crt \
  --client-name demo.example.dhttp.net \
  --client-cert /path/to/demo.example.dhttp.net.pem \
  --client-key /path/to/demo.example.dhttp.net.key \
  --host demo.example.dhttp.net \
  --addr 192.168.1.100:8080,192.168.1.101:8080
```

See [`examples/README.md`](examples/README.md) for example CLI parameters and response decoding notes.
