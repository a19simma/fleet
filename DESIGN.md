# Design: Console

The fleet-server web UI is an operator dashboard for jobs, tokens and credentials, behind passkey login. See [ADR-0041](docs/adr/0041-web-ui.md) for the framework decision.

## Direction

A dense, dark terminal console. References: GitHub dark dimmed (Primer) for colour and surface hierarchy, tmux status lines for density and the flat, bordered feel. The memorable part is keyboard-first dense rows beside a left sidebar: an operator scans many jobs at once and never reaches for the mouse.

## Tokens

All tokens live in `crates/fleet-server/ui/input.css` as daisyUI theme variables, named by role.

| Role | Value |
| --- | --- |
| Page surface (`base-100`) | `#0d1117` |
| Sunken surface (`base-200`) | `#090c10` |
| Border and raised surface (`base-300`) | `#1c232c` |
| Text (`base-content`) | `#c9d1d9` |
| Primary, success | `#3fb950` |
| Secondary, warning | `#d29922` |
| Accent, info | `#58a6ff` |
| Neutral | `#30363d` |
| Error | `#f85149` |

Each role has a `-content` colour for text on top of it, set in `input.css`.

- Radii: 2px for selectors, fields and boxes.
- Border: 1px. No depth, no noise, no shadows.
- Body: 13px monospace (`ui-monospace`, SF Mono, JetBrains Mono, Menlo, Consolas).
- Table rows: 0.15rem vertical cell padding. Gutter: 0.75rem.
- Focus: a 2px accent outline with 1px offset on `:focus-visible`.

## Rules

- Tailwind scans `crates/fleet-server/src/web` for class names. Every class is a literal string in Rust source. A name built at runtime (`format!("btn-{x}")`) is invisible to Tailwind and ships unstyled.
- Regenerate `crates/fleet-server/assets/ui.css` with `mise run css` and commit it. CI runs the build and fails on any diff. `mise run css:check` verifies locally.
- Use daisyUI 5 names: `fieldset` and `label`. `form-control` and the `*-bordered` variants are gone.
- The CSP is strict: no inline `style` attributes, no inline `<script>`. Style through classes and the stylesheet, script through files under `assets/`.
- The daisyUI plugin files are vendored under `crates/fleet-server/ui/vendor/`. See its README to update them.
