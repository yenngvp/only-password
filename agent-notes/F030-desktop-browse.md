# F030-desktop-browse

Built: `state/browse.rs` (Row, FieldRef, Detail, BrowseState, Session::new/refresh_rows, accessors `rows`, `search_text`, `selected`, `revealed`, `is_revealed`, and the actions). New `Screen::Detail(ItemId)`, `Action::{Search, Select, ToggleReveal, Back}`, `view::browse`/`view::detail`, `view::MASK` (eight U+2022).

Choices:
- Session fields `rows`, `search` (Zeroizing<String>), `detail`, `reveal` live in a private `BrowseState`; dropping the Session wipes them. `Session::refresh_rows()` is the hook later features call after any vault change (also drops a detail whose item is gone).
- Row is wiped by a manual `Drop` calling `Zeroize`; it also impls `ZeroizeOnDrop`. Debug of Row, Session, Detail (wrapper around StoredItem) is a fixed string.
- Masked toggle buttons are labelled "Reveal <name>" / "Hide <name>" (e.g. "Reveal Password", "Reveal PIN") so each is unique in the accessibility tree. Login Notes are always masked (placeholder even when empty, so length is not shown).
- ToggleReveal ignores fields the item lacks and non-hidden custom fields. Select works from Browse and Detail; a failed `get` returns to Browse with a notice. Search is only accepted on Browse.
- No clipboard feature exists yet, so no Copy button.
- Revealed text is drawn with `ui.label(secret.expose())`; egui necessarily copies it into its galley while shown.
