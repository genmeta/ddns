# Changelog

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
