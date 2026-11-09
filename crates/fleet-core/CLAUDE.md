# fleet-core

- **One hostile-text set.** `text::HOSTILE_RANGES` and `is_hostile` are the only list of characters to strip or refuse. Do not add a hand-cut table in another crate. A caller that needs blank or confusable characters (variation selectors, fillers) keeps a documented extra list on top, as `fleetd` `fetch.rs` does. Reject paths use `is_hostile_allowing_joiners`. See ADR-0063.
- **Unicode version.** The set is Unicode 16.0.0, tied to the `unicode-general-category` crate. The comparison test in `text.rs` fails when the crate moves. ADR-0063 lists the bump steps.
