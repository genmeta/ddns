# AWS Deployment Notes

`ddns-server` keeps QUIC/TLS/mTLS end-to-end in the backend process.

## Load Balancer

- Put an NLB in front of the server.
- Forward UDP, QUIC, TCP_UDP, or TCP_QUIC traffic to the backend without
  terminating TLS.
- Expose a separate TCP/HTTP/HTTPS health check port.

## Redis

- Use `redis_write_url` for the primary Redis endpoint.
- Use `redis_read_url` for the regional read replica or reader endpoint.
- `publish` and `clear` write only to the primary.
- `lookup` is read-only and can point at the replica.
- Expired index cleanup runs on the write path, not on lookup.

## Host Allowlist

- Configure `host_allowlist` with the suffixes this deployment owns.
- Example: `["genmeta.net"]`

## Extra UDP Services

- Keep STUN or custom UDP services on a separate NLB UDP listener and port.
- Do not multiplex them onto the QUIC listener unless the application does its own UDP demux.
