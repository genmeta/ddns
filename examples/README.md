# DDNS examples

This directory contains runnable examples for the published `dyns` package,
whose library target remains `ddns`.

| Example | Feature requirement | Purpose |
| --- | --- | --- |
| `mdns_discover` | `mdns` | Bind an mDNS service, publish sample local hosts, and print multicast packets. |
| `mdns_query` | `mdns` | Query a DHTTP name over local mDNS. |
| `query` | `h3` | Query a DNS-over-H3 server and decode the multi-record response. |
| `publish` | `h3` | Publish endpoint `E` records to a DNS-over-H3 server using client mTLS; H3 publish request headers are signed from the client endpoint identity. |

Run all commands from the `ddns/` repository.

## mDNS examples

Bind to a local interface and print multicast traffic:

```bash
cargo run --example mdns_discover --features mdns -- \
  --ip 127.0.0.1 \
  --device lo0
```

Query a name over mDNS:

```bash
cargo run --example mdns_query --features mdns -- \
  --ip 192.168.5.156 \
  --device en0
```

Replace `--ip` and `--device` with an address and interface that exist on the local machine.
The mDNS service name defaults to the build-time `DHTTP_MDNS_SERVICE` constant.

## DNS-over-H3 query

```bash
cargo run --example query --features h3 -- \
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
certificate is present, and endpoint signature verification status for signed `E` records.

## DNS-over-H3 publish

```bash
cargo run --example publish --features h3 -- \
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
| `--host <NAME>` | DNS host to publish. |
| `--addr <ADDR[,ADDR...]>` | One or more socket addresses to publish. |

The example imports `H3Publisher` from the `ddns::publishers` facade, but only needs the
`h3` backend feature because backend publisher types are re-exported from the facade directly.
H3 publish request headers are always signed with the configured client endpoint identity; callers no longer pass request signature fields.
