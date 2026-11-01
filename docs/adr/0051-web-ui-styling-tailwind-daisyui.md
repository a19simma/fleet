# Web UI styling: Tailwind and daisyUI, generated CSS committed

Status: Accepted 2026-11-01. Built in `crates/fleet-server/src/web/layout.rs` and `assets/ui.css`. Extends ADR-0041.

ADR-0041 chose Topcoat for the pages and left styling open. The first stylesheet was a hand-written file with a one-line rule. This ADR fixes how the web UI is styled from now on.

## Decision

- The stylesheet is Tailwind 4 with the daisyUI 5 plugin, in the dark `console` theme described in `DESIGN.md`.
- `ui/input.css` is the source. The Tailwind standalone CLI, pinned in `mise.toml`, builds `assets/ui.css` with `mise run css`. The CLI needs no Node.
- The generated `assets/ui.css` is committed. `include_str!` embeds it as `STYLE_CSS`, and `/static/style.css` serves it.
- CI runs `mise run css:check`, which rebuilds the file and fails when the committed copy differs.
- Every class name is a literal string in the Rust source under `src/web`. Tailwind scans that directory, so a class built with `format!` is never generated and ships unstyled.
- The daisyUI plugin files are vendored under `ui/vendor/`, so the build needs no network. `ui/vendor/README.md` lists the update steps.
- Every page renders through `shell` (signed-in pages, left sidebar) or `bare` (public pages) in `layout.rs`. Those two functions are the only place that emits the document skeleton, the stylesheet link, the skip link and `<main id="app">`, which carries `data-mode` and `data-csrf` for `passkey.js`.
- The CSP stays strict: no inline `style`, no inline script. `CSP` in `dispatch.rs` is one shared constant with a unit test that it holds no `'unsafe-inline'` and no `'unsafe-eval'`.

## Why

- daisyUI gives named components (`btn`, `table`, `menu`, `fieldset`) so page markup stays short and one theme file controls the look.
- A committed build keeps `cargo build` free of any CSS tool.
- The staleness check keeps the committed file honest.
- Literal class names are the price of Tailwind's source scan. The tests in `tests/web_shell.rs` check that every class on a page exists in `STYLE_CSS`.

## Consequences

- Any edit under `src/web` can change the scan result. Run `mise run css` after the last markup edit and commit `assets/ui.css`, or `css:check` fails.
- Inferred, not part of the design: the CLI output on Linux CI may differ byte for byte from the output on macOS. Equality is unproven until the `css` CI job runs.
- `harden` in `dispatch.rs` marks every web response `no-store`, so the browser fetches the stylesheet again on every page load.
