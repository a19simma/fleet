# Web UI

Status: Proposed 2026-10-29. Not built. Amends ADR-0013 (services). Evidence: `spikes/web/RESULT.md`.

Fleet has had the laptop `fleet` CLI as its only client. A browser UI for fleet view, Jobs and credentials needs a Rust web framework inside `fleet-server`. This ADR picks one and records what the spike showed.

## Decision

The web UI is embedded in `fleet-server` and built with Topcoat 0.11.0 (tokio-rs/topcoat, MIT, pre-1.0). It answers on the same port as gRPC. A dispatcher sends a request to tonic when the content type starts with `application/grpc` and the path starts with a registered gRPC service prefix, and to Topcoat otherwise.

### Spike outcome (CRED-00, from `spikes/web/RESULT.md`)

- **Coexistence: pass.** A tonic health RPC and a Topcoat page share one `TcpListener`. `topcoat::serve` cannot share a listener, so the server owns its accept loop with `hyper_util::server::conn::auto::Builder` (HTTP/1.1 and cleartext HTTP/2). `RouterService::call` is public, so no Topcoat internals are used.
- **Passkey: pass.** webauthn-rs 0.5.5 registers and logs in over Topcoat routes, driven by a software authenticator. The 0.6 releases are dev prereleases and were not used.
- **Asset embedding: pass only through a workaround.** Topcoat's `asset!` writes files to an `assets` directory beside the binary, and rendering a missing asset panics. Assets are served from a route over `include_str!`. The cost: no content-hashed URLs, no cache headers, one hand-written route per asset.
- **Negative test: pass.** A gRPC content type on a web route gets 4xx and the server keeps answering. Removing the path-prefix condition turned the test red.
- **Known gap.** Bypassing `topcoat::serve` drops its graceful-shutdown drain. The spike's accept loop has a plain stop signal only. The server needs its own drain before this ships.

### Pre-1.0 risk and pin policy

Topcoat has made 23 releases and 11 of them were breaking. Expect breakage on any bump. Pin it as `=0.11.0` in `Cargo.toml`, commit `Cargo.lock`, and treat each upgrade as its own change with the web tests run. Pin webauthn-rs the same way (`=0.5.5`).

### Fallback

The fallback is axum plus maud. It was not needed and was not built. It is the escape if Topcoat breaks in a way a pin cannot absorb: tonic already runs on axum, so the dispatcher and the routes would move with little rework.

## Consequences

- One port and one deployment. No second service, ingress or certificate.
- A hand-written accept loop and an asset route to maintain, and a shutdown drain to write.
- Topcoat upgrades are deliberate and may need route changes.
- Login and sessions are specified in ADR-0042.

## Considered and rejected

- **A separate web service.** A second deployment and a second port for a UI that reads the same Postgres.
- **A JavaScript single-page app.** A second toolchain and build step beside a Rust-only repo.
- **axum plus maud now.** Works, but gives up Topcoat's routing and components without a failure to justify it. Kept as the fallback.

## Unverified

- Topcoat under load and with long-lived streams. The spike ran short tests only.
- The `topcoat asset bundle` flow in a container image. Read from docs, not run.
- Whether openssl (pulled in by the test authenticator, dev only) matters for the production image.

## Amendment to ADR-0013 (services)

`fleet-server` also serves the web UI on the gRPC port, dispatched by content type and path prefix, as set above. The "gRPC through tonic" decision stands for every non-browser client.
