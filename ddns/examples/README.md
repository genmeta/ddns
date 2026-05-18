# DNS Server Documentation

## Introduction

`ddns` is a Rust-implemented DNS library that supports the mDNS (Multicast DNS) protocol and interacts with DNS servers via the HTTP/3 (H3) protocol for service discovery and publishing in local and remote networks. This document introduces how to use the example programs of `ddns` to publish and query DNS services, including detailed program parameters and HTTP packet structures.

## Building the Project

First, ensure you have a Rust environment. Clone or enter the project directory, then build:

```bash
cargo build -p ddns --features="h3x-resolver"
```

Note: The example programs require the `h3x-resolver` feature to enable HTTP/3 support.

## HTTP Packet Structure Overview

`ddns` uses the HTTP/3 protocol to transmit DNS queries and responses, similar to DNS over HTTPS (DoH) but based on the QUIC protocol. The structure of HTTP requests is as follows:

### URL Structure
- **Base URL**: Default `https://localhost:4433/`, used to specify the DNS server's address.
- **Path**: For queries, usually the root path `/`, the server parses the DNS query based on the request body.
- **Query Parameters**: Optional, used to specify query type or options.

### HTTP Headers
- **Content-Type**: `application/dns-message` (for DNS message body) or `application/json` (if using JSON format).
- **Accept**: `application/dns-message` or `application/json`.
- **User-Agent**: Client identifier.
- **Authorization**: If authentication is needed, use Bearer token or other mechanisms.

### Request Body (Body)
- DNS queries are sent in binary DNS message format (RFC 1035), containing query name, type (such as A, AAAA, SRV), and class.
- For publishing, the request body contains the DNS record data to be published.

### Response Body
- The server returns a DNS response message containing query results or confirmation of publishing.

## Usage Examples

### Publishing Services (publish)

Use the `publish` example to publish a DNS service record to the HTTP/3 DNS server.

#### Program Parameters
- `--base-url <URL>`: Base URL of the DNS server (default: `https://dns.genmeta.net:4433/`).
- `--server-ca <PATH>`: CA certificate PEM file path for verifying the online server certificate.
- `--client-name <NAME>`: Client identity name used for mTLS.
- `--client-cert <PATH>`: Client certificate chain PEM file.
- `--client-key <PATH>`: Client private key PEM file.
- `--sign`: Whether to sign the Endpoint record with the client private key (default: true).
- `--host <NAME>`: DNS name to publish, must match the SAN in the client certificate.
- `--addr <ADDR>`: List of socket addresses to publish, separated by commas.
- `--is-main`: Whether it is the main record (default: true).

#### Example Run Command
```bash
cargo run -p ddns --example publish --features="h3x-resolver" \
  --server-ca /path/to/root.crt \
  --client-name demo.example.genmeta.net \
  --client-cert /path/to/demo.example.genmeta.net.pem \
  --client-key /path/to/demo.example.genmeta.net.key \
  --host demo.example.genmeta.net \
  --addr 192.168.1.100:8080,192.168.1.101:8080
```

This command establishes an HTTP/3 connection to the server, sends a POST request containing DNS records, the server verifies the signature and stores the records.

### Querying Services (query)

Use the `query` example to query DNS service records from the HTTP/3 DNS server.

#### Program Parameters
- `--base-url <URL>`: Base URL of the DNS server (default: `https://dns.genmeta.net:4433/`).
- `--server-ca <PATH>`: CA certificate PEM file path for verifying the online server certificate.
- `--host <NAME>`: DNS name to query (default: `stun.genmeta.net`).

#### Example Run Command
```bash
cargo run -p ddns --example query --features="h3x-resolver" \
  --server-ca /path/to/root.crt \
  --host stun.genmeta.net
```

This command sends a GET or POST request to the server, the request body contains the DNS query message, the server returns matching records.

### Running the DNS Server (server)

Use the `server` example to start an HTTP/3 DNS server.

#### Program Parameters
- `--redis <URL>`: Optional Redis connection URL for persistent storage (default: none, uses in-memory storage).
- `--listen <ADDR>`: Server listen address (default: `127.0.0.1:4433`).
- `--server-name <NAME>`: Server name (default: `localhost`).
- `--cert <PATH>`: Server certificate PEM file (default: `examples/keychain/localhost/server.cert`).
- `--key <PATH>`: Server private key PEM file (default: `examples/keychain/localhost/server.key`).
- `--root-cert <PATH>`: Root CA certificate PEM file (default: `examples/keychain/localhost/ca.cert`).
- `--require-signature`: Whether to require client-signed records (default: true).
- `--ttl-secs <SECS>`: TTL time for records in seconds (default: 30).

#### Example Run Command
```bash
cargo run -p ddns-server -- --features="h3x-resolver" \
  --listen 127.0.0.1:4433 \
  --cert examples/keychain/localhost/server.cert \
  --key examples/keychain/localhost/server.key
```

After the server starts, it listens for HTTP/3 requests and handles publish and query operations.

## Other Examples

The project also includes other example programs such as `mdns_discover.rs` and `mdns_query.rs` for pure mDNS discovery and query operations, not involving HTTP/3. Please refer to the source code for more details.

## Notes

- Ensure that the local network supports QUIC and HTTP/3.
- Certificate and key files must be configured correctly, otherwise TLS handshake will fail.
- For production environments, use valid certificates and secure key management.
- For more configuration options, please refer to the project's main README.md file.
