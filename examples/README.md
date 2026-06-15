# DDNS examples

This directory contains runnable examples for the single published `dyns`
package, whose library target remains `ddns`.

| Example | Feature requirement | Purpose |
| --- | --- | --- |
| `mdns_discover` | none | Bind an mDNS service, publish sample local hosts, and print multicast packets. |
| `mdns_query` | none | Query a DHTTP name over local mDNS. |
| `query` | `h3x-resolver` | Query a DNS-over-H3 server and decode the multi-record response. |
| `publish` | `h3x-resolver` | Publish signed endpoint `E` records to a DNS-over-H3 server using client mTLS. |

Run all commands from the `ddns/` repository.

## mDNS examples

Bind to a local interface and print multicast traffic:

```bash
cargo run --example mdns_discover -- \
  --ip 127.0.0.1 \
  --device lo0
```

Query a name over mDNS:

```bash
cargo run --example mdns_query -- \
  --ip 192.168.5.156 \
  --device en0
```

Replace `--ip` and `--device` with an address and interface that exist on the
local machine. The mDNS service name defaults to the build-time
`DHTTP_MDNS_SERVICE` constant.

## DNS-over-H3 query

```bash
cargo run --example query --features h3x-resolver -- \
  --server-ca /path/to/root.crt \
  --host nat.genmeta.net
```

Options:

| Option | Meaning |
| --- | --- |
| `--base-url <URL>` | DNS-over-H3 server base URL. Defaults to build-time `DHTTP_H3_DNS_SERVER` with a trailing slash. |
| `--server-ca <PATH>` | PEM root CA used to verify the DNS server certificate. |
| `--host <NAME>` | DNS host to query. Defaults to `nat.genmeta.net`. |

The example sends `GET /lookup?host=<NAME>`. A successful server response is a
`ddns::core::wire::MultiResponse` body with header `x-record-format: multi`:

```text
u32 count
repeated count times:
  u32 dns_len | dns packet bytes | u32 cert_len | DER publisher certificate bytes
```

The example prints each DNS packet, the publisher certificate fingerprint when a
certificate is present, and endpoint signature verification status for signed
`E` records.

After the server starts, it listens for HTTP/3 requests and handles publish and query operations.
If the configured server certificate includes its issuer chain, the process also
fetches and refreshes its own stapled OCSP response from cert-server's public
`/ocsp` endpoint. When the PEM only contains the leaf certificate, configure
`ocsp_issuer_cert` in `server.toml`. The same config file also supports
`redis_write_url`, `redis_read_url`, and `host_allowlist` for AWS-style
primary/replica Redis and domain suffix controls.

## DNS-over-H3 publish

```bash
cargo run --example publish --features h3x-resolver -- \
  --server-ca /path/to/root.crt \
  --client-name demo.example.dhttp.net \
  --client-cert /path/to/demo.example.dhttp.net.pem \
  --client-key /path/to/demo.example.dhttp.net.key \
  --host demo.example.dhttp.net \
  --addr 192.168.1.100:8080,192.168.1.101:8080
```

Options:

| Option | Meaning |
| --- | --- |
| `--base-url <URL>` | DNS-over-H3 server base URL. Defaults to build-time `DHTTP_H3_DNS_SERVER` with a trailing slash. |
| `--server-ca <PATH>` | PEM root CA used to verify the DNS server certificate. |
| `--client-name <NAME>` | DHTTP identity name presented by the client endpoint. |
| `--client-cert <PATH>` | Client certificate chain PEM for mTLS and endpoint signature verification. |
| `--client-key <PATH>` | Client private key PEM. |
| `--sign <true|false>` | Whether to sign each endpoint `E` record. Defaults to `true`. |
| `--host <NAME>` | DNS host to publish. Standard-policy servers require this to match the client certificate DNS SAN. |
| `--addr <ADDR[,ADDR...]>` | One or more socket addresses to publish. |

The example derives the endpoint selector from the client certificate SKI before
signing records. Use the correct certificate chain instead of manual selector
flags.

The example sends `POST /publish?host=<NAME>` with a binary DNS packet body. For
Standard policy domains, the server requires a client certificate whose single
DNS SAN matches `host`; when `require_signature = true`, at least one signed
endpoint record must verify against the publisher certificate. Open-multi policy
domains still require client mTLS but skip the host SAN and endpoint signature
checks.

## Running the server

```bash
cargo run --bin ddns-server --features server -- --config server.toml
```

`server.toml` documents the available fields: listener, TLS identity, client root
CA, optional Redis storage, TTL, domain policies, and static seed records.

