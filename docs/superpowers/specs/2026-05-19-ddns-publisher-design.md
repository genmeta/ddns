# DDNS Publisher Design

## Goal

Add a reusable DNS publisher for DHTTP endpoints. The publisher signs endpoint records with the endpoint identity and publishes them through concrete DNS publishers discovered from the endpoint resolver set.

## Decisions

- `LocalAuthority` and `RemoteAuthority` are identity-layer concepts. Move their async trait definitions to `dhttp-identity`; `Identity` implements them without adding generics to `Identity`.
- `LocalAuthority` remains an async signing API. It is an async/remote-capable counterpart of `rustls::sign::SigningKey`, not a replacement with synchronous signing.
- DNS publisher code lives in the `ddns` crate. `dhttp::Endpoint` only exposes a convenience method that constructs a `ddns::Publisher` from endpoint state.
- `Endpoint::publisher()` returns `Result<ddns::Publisher, CreatePublisherError>` because anonymous endpoints cannot publish signed DNS records. `Publisher` stores a non-optional identity.
- `EndpointAddr::sign_with(SigningKey, scheme)` is removed. Endpoint record signing uses `dhttp_identity::LocalAuthority`.
- Signature scheme selection follows the existing `pick_signature_scheme` preference order: Ed25519, ECDSA P-256, ECDSA P-384, RSA-PSS SHA-256/384/512, RSA-PKCS1 SHA-256/384/512. The async authority API is not expanded with `choose_scheme`; signing tries compatible schemes and treats `UnsupportedScheme` as a cue to try the next candidate.
- `publish_once` returns an error for the first failed publish attempt. `run` publishes every 20 seconds, logs warnings on failures with `snafu::Report`, and does not retain failure state.
- `NoPublisherResolver` is built at publish time when no concrete publisher can be found by downcasting.
- There is no `Resolvers::publish`; publishing is resolver-specific and uses `Any` downcasting.

## Data Flow

`dhttp::Endpoint::publisher()` clones the endpoint identity, network, resolver, and bind patterns into `ddns::Publisher`. `Publisher::publish_once()` collects endpoint addresses, builds signed DNS packets, and dispatches them to concrete publishers:

- H3 and HTTP publishers receive public/STUN-derived endpoint addresses.
- mDNS publishers receive only local QUIC addresses on the same network device and IP family as the mDNS binding.

Each DNS packet is independently signed with the endpoint identity before publication.

## Error Handling

Errors are typed with `snafu`. Display messages are lower-case fragments and do not repeat source errors. `publish_once` returns structured errors; `run` logs `snafu::Report` and continues.

## Testing

Unit tests cover authority-based endpoint signing, signature scheme fallback, anonymous endpoint publisher construction, missing publisher reporting, and mDNS address scoping helpers. Workspace tests and clippy run before commits.
