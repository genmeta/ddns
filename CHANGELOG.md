# Changelog

## [0.8.0] - 2026-10-12

### Changed

- Adapt resolvers and publishers to the current QUIC identity and discovery APIs.
- Maintain mDNS interface resources and report H3 lookup responses and failures.
- Use published dhttp 0.7.0, dhttp-home 0.6.0 and QUIC dependencies.

- Keep the reqwest HTTP client on standard rustls while QUIC uses qrustls.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `dyns` | 0.7.2 | 0.8.0 |


## [0.7.2] - 2026-08-19

### Changed

- Align the production DHTTP bootstrap constants shared by resolver and
  publisher integrations.

### Dependencies

- Release manifests continue to target `dquic` v0.7.1 and `h3x` v0.6.1.

## [0.7.1] - 2026-08-11

### Fixed

- Share mDNS binding lifecycles across resolver users and constrain multicast
  queries to the requested service and address family.
- Preserve service and address-family lookup semantics through HTTP and H3
  resolvers.

### Dependencies

- Release manifests target `dquic` v0.7.1 and `h3x` v0.6.1.
