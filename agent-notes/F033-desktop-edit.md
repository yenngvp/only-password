# F033-desktop-edit

Built: `state/edit.rs` (Draft, DraftField, add/edit/delete actions), `Screen::Edit(Option<ItemId>)`,
views `view::edit`, `view::secret_edit_with` (reveal-capable variant; `secret_edit` is unchanged),
Add Login / Add Note on Browse, Edit / Delete (+ "Confirm delete" / "Cancel delete") on Detail.
Tests: `tests/edit.rs`.

Choices:
- The Draft lives in the private BrowseState inside Session, so Lock, idle expiry and `on_exit` drop it.
  `delete_pending` is there too.
- Plain fields are edited through setter actions (`SetTitle`, `SetUrl(i, ..)`, ...). Secret text never goes
  through an `Action` (Actions derive Debug/Clone); the view and tests type into `draft_mut()` buffers.
- All custom-field values are `SecretBuf`; they are masked only when the field's hidden flag is set
  (reveal per field via `ToggleDraftReveal(FieldRef)`; `Custom(i)` entries are cleared when a field is removed).
- Kind switch (`SetKind`, offered only when adding) keeps the login values in the draft but `to_item`
  submits only title and notes for a note, and the form shows only those.
- Empty username, password and TOTP secret become `None`. A non-empty TOTP secret goes through
  `normalize_totp_secret`; its failure is the core's InvalidInput message.
- Back, Select, Search and ShowSettings while on the edit screen drop the draft first (Back only does that).
  `CancelDraft` returns to the detail (edit) or browse (add).
- Notes are edited with a single-line masked field (`secret_edit`), as the spec routes secret fields through it.
- Typed period text that fails to parse becomes 0, which the core rejects on save.
