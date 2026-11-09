# One hostile-text set

Status: Proposed 2026-11-09, built (SAN-1a to SAN-1k). Amends ADR-0062 decision 2 (scope of the sanitiser). Builds on ADR-0022 and ADR-0062.

Before this change six places kept their own hand-cut list of characters to strip or refuse: the CLI, the fleetd shell recorder, the CI log cleaner, the proto validators, the profile prompt validator and the fetch body check. The lists could disagree, and the fetch table claimed Unicode 18.0.0 while the crate that tests it ships 16.0.0.

## Decision

1. **One set, in `fleet_core::text`.** `HOSTILE_RANGES` is the `Cf`, `Zl` and `Zp` code points of `UnicodeData.txt`, plus the tag block `U+E0000..=U+E007F`. `is_hostile(c)` adds `Cc` through `char::is_control`. A test compares the set with the `unicode-general-category` crate for every scalar value, so a hand edit cannot drift from the data. Strip paths and reject paths use this set and no other.
2. **Strip paths use `is_hostile`.** `sanitise_text` and `sanitise_lines` run redact, strip, redact, strip, cut. The first redaction matches a secret that itself holds a stripped character. The first strip lets a secret split by a hidden character match in the second redaction. The second strip removes what the redactions joined. The cut comes last so a secret straddling the cap leaves no prefix. `strip_keeping_lines` keeps newline and tab. This replaces the order in ADR-0062 decision 2, which stripped before it redacted, and widens that decision from transcript fields to every strip path: the CLI, the web timing view, the fleetd shell recorder and the CI log cleaner.
3. **Reject paths use `is_hostile_allowing_joiners`, which is `is_hostile` minus `U+200C..=U+200F`.** The proto plain-text and CI log validators and the profile validators refuse a value instead of cleaning it. Emoji sequences and Persian, Hindi and Hebrew text need ZWNJ and ZWJ, and a refusal cannot take them out without refusing the user's text. The carve-out applies to reject paths only. Strip paths remove all four, because a joiner can split a secret past exact-match redaction and a strip path has already decided to alter the text. The profile prompt validator adds `U+200E` and `U+200F` back, so profile prompt text is stricter than proto plain text, which accepts the left-to-right and right-to-left marks. The CI log cleaner in `crates/fleetd/src/runner/ci.rs` strips all four, and `is_ci_log` accepts joiners, so a cleaned log always validates.
4. **Blank and confusable characters stay out of the shared set.** `U+034F`, `U+115F`, `U+1160`, `U+3164`, `U+FFA0`, `U+17B4`, `U+17B5`, `U+2800` and the variation selectors are not `Cc`, `Cf`, `Zl` or `Zp`, and `U+2800` and the variation selectors occur in legitimate text. A caller that needs a stricter rule keeps its own documented extra list. `crates/fleetd/src/fetch.rs` does: `EXTRA_BLANK_RANGES` holds `U+034F`, the Hangul fillers, the Khmer inherent vowels `U+17B4` and `U+17B5`, and both variation selector ranges, and a fetched body holding one is refused whole. `U+2800` is not in it, because braille text uses it.
5. **Unicode version and bump procedure.** The set is Unicode 16.0.0, the version `unicode-general-category` 1.1.0 reports in `UNICODE_VERSION`. To move to a newer version: bump that crate, run `cargo test -p fleet-core`, which fails on any scalar whose category changed, regenerate `HOSTILE_RANGES` from the new `UnicodeData.txt`, edit the version in the `text.rs` rustdoc, rerun the fleetd and server tests, and record the bump in this ADR. No file claims a Unicode version the crate does not ship.

## Consequences

- A character added to the set takes effect on every strip and reject path at once. A path cannot forget it.
- A reject path accepts ZWNJ and ZWJ. A stored value can hold one, and any later strip path removes it. A secret split by ZWJ in a stored value is caught only when the value passes a strip path before redaction, which the sanitiser order guarantees for transcripts and shell commands.
- The broker, proto and profile reject paths accept `U+200C` and `U+200D`. A broker Low finding stays open: a ZWJ inside a secret can split it past exact-match redaction when the value is rejected or stored rather than stripped.
- Tag characters are refused as a block, so emoji tag flag sequences such as the England, Scotland and Wales flags are refused on reject paths and stripped on strip paths.
- The broker check name redactor holds the static token, the leased token and every installation token by shape, so a check name never shows a GitHub token.
- The CLI stream scrubber strips each piece before it redacts, so a secret that itself holds a hostile character is not matched in a stream. A bearer token cannot hold one.
- A fetched body accepts unassigned and private-use code points (`Cn`, `Co`). Only the shared set and the fetch extra list refuse a body.
- Profile prompts refuse the direction marks that proto plain text accepts. The two differ on purpose and the tests pin both.
- A fetched body with a variation selector, which emoji presentation uses, is refused. The refusal is the existing behaviour.

## Considered and rejected

- **One set with no joiner carve-out.** It refuses Persian, Hindi, Hebrew and emoji text in profile names, labels and similar fields.
- **A joiner carve-out on strip paths too.** It leaves the secret-splitting hole open for the paths that already alter text.
- **Adding the blank characters to the shared set.** It strips legitimate braille and emoji presentation text from every transcript.
