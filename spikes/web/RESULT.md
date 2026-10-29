# CRED-00 result: Topcoat, tonic and webauthn-rs in one process

Framework that passed: Topcoat 0.11.0. The plain axum plus maud fallback was not built because Topcoat met all three checks.

| Check | Result | Notes |
| --- | --- | --- |
| 1. Coexistence on one port | pass | tonic health RPC and a Topcoat page share one `TcpListener`. |
| 2. Asset embedding | pass with a workaround | `include_str!` served by a Topcoat route. Topcoat's own `asset!` bundler does not embed (see below). |
| 3. Passkey register and login | pass | `webauthn-authenticator-rs` `SoftPasskey` drives the HTTP routes end to end. |
| Negative: gRPC content type on web routes | pass | 4xx, no panic, server keeps answering. |

## Versions (pinned in `Cargo.toml`, `Cargo.lock` committed)

- topcoat `=0.11.0` (MIT, pre-1.0, rust-version 1.99)
- tonic `=0.14.6`, tonic-health `=0.14.6` (same tonic as the repo root)
- hyper-util `=0.1.21`
- webauthn-rs `=0.5.5`, webauthn-authenticator-rs `=0.5.5` with `softpasskey` (dev-dependency). The `0.6.x-dev` prereleases were not used.
- toolchain: cargo 1.99.1

## Check 1: coexistence

Topcoat serves only through its own accept loop (`topcoat::serve`, `internal_serve`) and exposes no tower `Service` over a generic body. `RouterService` implements `hyper::service::Service<Request<Incoming>>`. tonic's `Routes` is a tower service over an axum router. The spike did not try an axum `Router` merge and owns the accept loop instead:

- `src/dispatch.rs`: `hyper_util::server::conn::auto::Builder` serves HTTP/1.1 and cleartext HTTP/2 prior knowledge on one listener. `Dispatch::handle` sends a request to tonic when the content type starts with `application/grpc` and the path starts with `/grpc.health.v1.Health/`, otherwise to `RouterService`. Both bodies are boxed to one type.
- Topcoat's `RouterService::call` is public, so no Topcoat internals are used. `topcoat::serve` is bypassed, so Topcoat's graceful shutdown drain and dev-server notification do not run. The spike has a plain stop signal only.
- Test `coexistence_grpc_health_and_web_page_on_one_port`: a tonic `HealthClient` (h2) gets `SERVING`, and a reqwest HTTP/1.1 GET of `/` returns the page. No `grpcurl` is installed on the machine, so a tonic client test replaces it.

Blocker if the production server wants an axum-only merge: Topcoat has no axum-router mount for its own routes. The reverse exists (`topcoat::router::tower::TowerRoute` mounts a tower service inside Topcoat, feature `tower`), but it was not used because gRPC trailers and streaming need the raw hyper path.

## Check 2: asset embedding

Topcoat's `asset!` macro does not embed files. Per `topcoat-0.11.0/docs/asset.md`, "Topcoat bundles the files after building your application": the `topcoat asset bundle` CLI scans the compiled binary and copies files to an `assets` directory beside the executable, which `AssetBundle::load` reads at runtime. "Rendering an Asset that is missing from the loaded bundle panics." Only the manifest can be embedded (`Manifest::parse(include_str!(..))`), and only for externally hosted assets. This was read from source and docs and not exercised.

Workaround that passes: `src/web.rs` serves `include_str!("../assets/style.css")` from a `#[route(GET "/static/style.css")]`, so the bytes live in the binary. Test `embedded_asset_is_served_from_the_binary` asserts status, `text/css` and byte equality. Cost: no content hash in the URL, no cache headers, hand-written per asset.

## Check 3: passkey

- `src/passkey.rs`: `Passkeys` wraps `Webauthn` with an in-memory user map and hand-written `PasskeyError`.
- `src/web.rs`: `POST /passkey/register/{start,finish}` and `/passkey/login/{start,finish}` as Topcoat `#[route]` JSON handlers. State arrives through `app_context`.
- Test `passkey_register_and_login_with_software_authenticator`: `WebauthnAuthenticator::new(SoftPasskey::new(true))` registers and logs in over real HTTP. A replayed assertion gets 400 and an unknown user gets 400.
- Topcoat's default origin policy guards POST routes. The tests send `Origin` equal to the configured origin and the router trusts it with `OriginPolicy::trust_origins`. `webauthn-authenticator-rs` pulls in openssl (`crypto` feature); it built on this machine.

## Negative test

`grpc_content_type_on_web_routes_gets_4xx_and_server_survives` over HTTP/2 prior knowledge:

- `POST /`, `POST /passkey/register/start` and `POST /static/style.css` with `content-type: application/grpc` return 4xx (the path is outside the gRPC service prefix, so the Topcoat route table answers; the test asserts only the 4xx class).
- `POST /grpc.health.v1.Health/Check` with `content-type: application/json` goes to the web stack and returns 4xx.
- `POST /passkey/register/start` with `content-type: text/plain` returns 4xx.
- A later `GET /` returns 200 and the server task is still running.

Mutation check: removing the path-prefix condition from `Dispatch::is_grpc` turned this test red (tonic then answered the `application/grpc` request to `/`).

## How to run

```sh
cd spikes/web
mise exec -- cargo test
mise exec -- cargo fmt --check
mise exec -- cargo clippy --all-targets -- -D warnings
ADDR=127.0.0.1:3000 mise exec -- cargo run
```

Build and test took about 8 s after the first dependency fetch.

## Code pointers

- `spikes/web/src/dispatch.rs`: accept loop and content-type routing
- `spikes/web/src/web.rs`: Topcoat page, asset route, passkey routes
- `spikes/web/src/passkey.rs`: webauthn-rs wrapper
- `spikes/web/src/main.rs`: wiring on one `ADDR`
- `spikes/web/tests/spike.rs`: the four checks
