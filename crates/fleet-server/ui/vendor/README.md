# Vendored daisyUI

- Version: daisyUI 5.7.50
- Source: npm `daisyui@5.7.50` (https://www.npmjs.com/package/daisyui, https://github.com/saadeghi/daisyui)
- Licence: MIT
- Files: `daisyui.mjs` and `daisyui-theme.mjs`, copied unmodified from the npm package root.

Tailwind loads both as plugins from `../input.css`. They are committed so the CSS build needs no Node or network.

## Update

1. `npm pack daisyui@<version>` and unpack the tarball.
2. Copy `daisyui.mjs` and `daisyui-theme.mjs` from the package root over the files here.
3. Change the version above.
4. Run `mise run css` and commit the regenerated `crates/fleet-server/assets/ui.css`.
