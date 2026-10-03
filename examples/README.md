# dyns examples

Run these commands from the `ddns/` repository. The package is named `dyns` and
keeps the Rust library name `ddns`.

## DNS-over-H3 query

```bash
cargo run --example query --features h3 -- \
  --host sky.lee.dhttp.net
```

`--server-origin` defaults to the build-time `DHTTP_NAME_SERVICE`
(`https://ddns.genmeta.net`). The example registers System DNS for bootstrap,
initializes `DhttpNetwork`, sends `GET /api/v2/lookup` through `dhttp::Anonymous`,
and prints decoded endpoint records. Add `--identity alice.smith.dhttp.net` to
bind requests to a named endpoint. Its credentials are loaded once from the
identity profile under `DHTTP_HOME` (default: `~/.dhttp/`).

Applications can register `Arc<H3Resolver>` with `qresolve::Resolver::add`.
Register a bootstrap source such as `qresolve::SystemResolver` as well: the
H3 resolver skips its own server hostname to avoid recursive resolution.

## DNS-over-H3 publish

```bash
cargo run --example publish --features h3 -- \
  --identity alice.smith.dhttp.net \
  --host alice.smith.dhttp.net \
  --addr 192.0.2.10:4433,192.0.2.11:4433
```

Publishing loads the endpoint identity’s certificate, private key, and OCSP staple
from its profile and signs with `qtls::LocalAuthority` through the same H3
resolver. It writes the existing `/api/v2/publish` wire format.
The request uses the new dhttp window writer and closes the upload with
`shutdown()` before awaiting the response.

## mDNS query

```bash
cargo run --example mdns_query --features mdns -- \
  --ip 192.168.5.156 \
  --device en0 \
  --host sky.lee.dhttp.net
```

Use an address and interface present on the local machine. The service name
defaults to `DHTTP_MDNS_SERVICE_DOMAIN`.
