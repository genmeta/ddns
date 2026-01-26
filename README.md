# GMDNS

GMDNS is a high-performance mDNS (Multicast DNS) protocol library built with Rust, specifically designed for P2P network discovery and NAT traversal scenarios. It supports the standard RFC 6762 protocol while extending endpoint discovery capabilities through custom resource records, enabling publication and verification of both direct and relay addresses. Additionally, it integrates HTTP/3 support for secure DNS over HTTP/3 (DoH3) interactions with remote DNS servers.

## 🌟 Key Features

- **Standards Compliant**: Supports standard DNS packet format and mDNS multicast discovery.
- **P2P Enhanced**: Custom `E` record type supporting IPv4/IPv6 direct and relay addresses.
- **Security Verification**: Built-in signature schemes (Ed25519, etc.) ensuring endpoint data authenticity and integrity.
- **High Performance Parsing**: Zero-copy parsing framework based on `nom` for blazing-fast packet processing.
- **Async-Driven**: Fully compatible with `tokio` async runtime for high-concurrency network environments.
- **HTTP/3 Integration**: Supports DNS over HTTP/3 (DoH3) for secure remote DNS queries and publishing.

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
gmdns = { path = "../gmdns" }
```

For HTTP/3 features, enable the `h3x-resolver` feature:

```toml
[dependencies]
gmdns = { path = "../gmdns", features = ["h3x-resolver"] }
```

### Simple mDNS Discovery Example

```rust
use gmdns::mdns::Mdns;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Create mDNS instance
    let mdns = Mdns::new("_genmeta.local", "127.0.0.1".parse().unwrap(), "lo0")?;
    
    // Listen to discovery stream
    let mut stream = mdns.discover();
    while let Some((addr, packet)) = stream.next().await {
        println!("Discovered packet from {}: {:?}", addr, packet);
    }
    Ok(())
}
```

### HTTP/3 DNS Publishing Example

```rust
use gmdns::resolver::h3_resolver::H3Resolver;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = H3Resolver::new(
        "https://localhost:4433/",
        Path::new("examples/keychain/localhost/ca.cert"),
        "client",
        Path::new("examples/keychain/localhost/client.cert"),
        Path::new("examples/keychain/localhost/client.key"),
    )?;

    // Publish a DNS record
    resolver.publish("client.genmeta.net", "127.0.0.1:5555").await?;
    Ok(())
}
```

---

## 🌐 HTTP/3 DNS Server

GMDNS includes support for DNS over HTTP/3 (DoH3), allowing secure publication and querying of DNS records via HTTP/3 protocol. This is useful for remote networks where multicast mDNS is not feasible.

### Publishing Services

Publish DNS service records to an HTTP/3 DNS server:

```bash
cargo run --example publish --features="h3x-resolver" \
  --base-url https://localhost:4433/ \
  --host client.genmeta.net \
  --addr 192.168.1.100:8080
```

### Querying Services

Query DNS service records from an HTTP/3 DNS server:

```bash
cargo run --example query --features="h3x-resolver" \
  --base-url https://localhost:4433/ \
  --host client.genmeta.net
```

### Running the DNS Server

Start an HTTP/3 DNS server:

```bash
cargo run --example server --features="h3x-resolver" \
  --listen 127.0.0.1:4433 \
  --cert examples/keychain/localhost/server.cert \
  --key examples/keychain/localhost/server.key
```

For detailed parameters and HTTP packet structures, see [examples/README.md](examples/README.md).

---

## 📖 Protocol Specification

### 1. Packet Layout

DNS packets consist of a fixed header and four variable-length sections:

```text
+---------------------+-----------------------+-----------------------+-----------------------+-----------------------+
| Header (12 bytes)   | Question Section      | Answer Section        | Nameserver Section    | Additional Section    |
+---------------------+-----------------------+-----------------------+-----------------------+-----------------------+
| Transaction ID      | Query list            | Answer RR list        | Authority RR list     | Additional RR list    |
| and Flags           |                       |                       |                       |                       |
+---------------------+-----------------------+-----------------------+-----------------------+-----------------------+
```

#### 1.1 Header
Fixed length of 12 bytes. Contains ID, Flags, and counters for subsequent sections (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT).

#### 1.2 Resource Record
Answer, Nameserver, and Additional sections all use this format:

- **NAME**: Variable-length domain name, supports RFC 1035 compression.
- **TYPE (u16)**: Record type (e.g., A=1, SRV=33, E=266).
- **CLASS (u16)**: Protocol class. In mDNS, the highest bit (bit 15) is used for cache-flush flag.
- **TTL (u32)**: Cache time-to-live (seconds).
- **RDLEN (u16)**: Length of resource data (RDATA).
- **RDATA**: Specific resource content, format determined by TYPE.

### 2. Custom Type Definitions (QType)

| Type     | Value | Description      | RDATA Format                      |
| :------- | :---- | :--------------- | :-------------------------------- |
| **A**    | 1     | IPv4 address     | 4-byte IP                         |
| **AAAA** | 28    | IPv6 address     | 16-byte IP                        |
| **SRV**  | 33    | Service location | Priority + Weight + Port + Target |
| **E**    | 266   | Endpoint address | Flags + Seq + Addr(s) + [Sig]     |

### 3. Endpoint Extensions (Type E)

#### 3.1 RDATA Wire Format

##### Packet Format

```text
+--------+-----------------+--------------------+----------------------------+
| flags  | sequence(varint)| addr(s)            | signature (optional)       |
+--------+-----------------+--------------------+----------------------------+
| u8     | QUIC varint     | v4: 2+4 / v6: 2+16 | scheme(u16)+len(varint)+N  |
+--------+-----------------+--------------------+----------------------------+
```

##### flags (u8) Field Definition:
- bit 7 (0x80): **FAMILY** - Address family (0=IPv4, 1=IPv6)
- bit 6 (0x40): **MAIN** - Primary address flag
- bit 5 (0x20): **SEQUENCED** - Sequence number present
- bit 4 (0x10): **FORWARD** - Connection type (0=direct, 1=relay)
- bit 3 (0x08): **SIGNED** - Signature present
- bits 2-0: Reserved

##### Address Format:
- **Direct**: `port(u16)` + `IP(u32/u128)`
- **Relay**: `outer_port(u16)` + `outer_IP(u32/u128)` + `agent_port(u16)` + `agent_IP(u32/u128)`
- **sequence**: DNS record sequence number. Records with the same sequence are considered from the same machine and can use multipath connections.
- **signature**: When `SIGNED` flag is set, signature field is appended.

#### 3.2 Flag Bit Masks

- `0b1000_0000`: **FAMILY** (Address family: 0=IPv4, 1=IPv6)
- `0b0100_0000`: **MAIN** (Primary address flag)
- `0b0010_0000`: **SEQUENCED** (Sequence number present)
- `0b0001_0000`: **FORWARD** (Connection type: 0=direct, 1=relay)
- `0b0000_1000`: **SIGNED** (Signature present)

#### 3.3 Address Format Details

- **Direct**: `Port(u16)` + `IP(u32/u128)`
- **Relay**: `OuterPort(u16)` + `OuterIP(u32/u128)` + `AgentPort(u16)` + `AgentIP(u32/u128)`

#### 3.4 Signature Format

When signature is present: `Scheme (u16)` + `Length (VarInt)` + `Data (N bytes)`.

---

## 🛠 Project Structure

- `src/parser/`: Core protocol parsing implementation (Nom parsers).
- `src/protocol.rs`: UDP multicast and packet routing logic.
- `src/mdns.rs`: High-level mDNS discovery and response API.
- `src/resolver/`: HTTP/3 resolver implementation for DoH3 support.
- `examples/`: Sample code including mDNS discovery/query, and HTTP/3 publishing/querying/server examples.
