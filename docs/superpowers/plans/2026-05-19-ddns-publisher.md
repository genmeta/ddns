# DDNS Publisher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add signed DNS publishing for DHTTP endpoints using async identity authorities and concrete ddns publishers.

**Architecture:** `dhttp-identity` owns async authority traits and signature helpers. `ddns-core` signs endpoint records through `LocalAuthority`. `ddns` owns `Publisher`, discovers concrete publishers by downcasting, and publishes signed packets. `dhttp::Endpoint` provides the convenience constructor.

**Tech Stack:** Rust 2024, snafu, futures BoxFuture, dhttp-identity, ddns-core, ddns, h3x/dquic resolver traits.

---

### Task 1: Move async authority traits into dhttp-identity

**Files:**
- Modify: `dhttp/identity/src/identity.rs`
- Modify: `dhttp/identity/src/lib.rs`
- Delete: `h3x/src/quic/authority.rs`
- Modify: h3x call sites to import `dhttp_identity::identity::{LocalAuthority, RemoteAuthority, SignError, VerifyError}` directly

- [ ] Add tests in `dhttp/identity/src/identity.rs` for `Identity` implementing async `LocalAuthority` and sync-default `RemoteAuthority` verification behavior.
- [ ] Move `LocalAuthority`, `RemoteAuthority`, `extract_public_key`, `verify_signature`, and `sign_with_key` equivalents into `dhttp-identity` while preserving async signatures.
- [ ] Delete `h3x::quic::authority`; downstream crates import the identity authority API from `dhttp_identity::identity` directly.
- [ ] Run `cargo test -p dhttp-identity` and `cargo test --features dquic` in h3x.

### Task 2: Replace ddns-core SigningKey signing with LocalAuthority signing

**Files:**
- Modify: `ddns/ddns-core/Cargo.toml`
- Modify: `ddns/ddns-core/src/parser/record/endpoint.rs`
- Modify: `ddns/ddns-core/src/parser/sigin.rs`

- [ ] Add a failing async test for signing an `EndpointAddr` through a fake `LocalAuthority` that rejects the first preferred compatible scheme and accepts the next one.
- [ ] Add `EndpointAddr::sign_with_authority(&mut self, authority: &(impl LocalAuthority + ?Sized)) -> impl Future<Output = Result<(), SignEndpointError>>`.
- [ ] Keep old low-level `ddns_core::parser::sigin::sign_with_key(SigningKey, SignatureScheme, data)` helper, delete only the `EndpointAddr::sign_with(SigningKey, SignatureScheme)` convenience method, and update tests/examples to use the async authority method where endpoint records are signed.
- [ ] Keep verification logic unchanged except for imports.
- [ ] Run `cargo test -p ddns-core`.

### Task 3: Implement ddns Publisher

**Files:**
- Create: `ddns/ddns/src/publisher.rs`
- Modify: `ddns/ddns/src/lib.rs`
- Modify: `ddns/ddns/src/resolvers.rs`
- Modify: `ddns/gmdns/src/resolvers/mdns.rs` if mDNS needs a public binding iterator

- [ ] Add tests for `NoPublisherResolver`, downcast discovery, and mDNS same-device/same-family address filtering.
- [ ] Implement `Publisher` with non-optional identity, network, resolver, bind patterns, and 20s default interval.
- [ ] Implement `publish_once` to build signed packets and publish via concrete H3, HTTP, and mDNS publishers discovered through `Any` downcasts.
- [ ] Implement `run` as an infinite async loop that logs warning reports and sleeps 20 seconds between attempts.
- [ ] Run `cargo test --workspace --all-features` in ddns.

### Task 4: Add dhttp Endpoint publisher entry point

**Files:**
- Modify: `dhttp/dhttp/src/endpoint.rs`
- Modify: `dhttp/dhttp/src/lib.rs` if re-export plumbing is needed

- [ ] Add a test or compile-time assertion for anonymous endpoint returning `CreatePublisherError::AnonymousEndpoint`.
- [ ] Implement `Endpoint::publisher(&self) -> Result<ddns::Publisher, ddns::CreatePublisherError>`.
- [ ] Run `cargo test --workspace` in dhttp.

### Task 5: Verification and commits

**Files:**
- All modified files above

- [ ] Run `cargo fmt` in dhttp, h3x, and ddns.
- [ ] Run `cargo clippy --all-targets --all-features -- -D warnings` in dhttp and ddns.
- [ ] Run `cargo clippy --all-targets --features "dquic,hyper,serde,webtransport,testing" -- -D warnings` in h3x.
- [ ] Run relevant cargo tests in all touched repos.
- [ ] Commit each independent repo with a semantic message.
