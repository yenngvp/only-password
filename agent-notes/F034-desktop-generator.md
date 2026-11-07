# F034-desktop-generator

Built: `state/generator.rs` (GeneratorState, GeneratorMode, generator actions), `Screen::Generator`,
`view::generator_panel` (side panel in the edit screen via `egui::Panel::right`, standalone screen from Browse),
`tests/generator.rs`.

Choices:
- GeneratorState lives in the private BrowseState, so Lock/idle/exit drop it (value is a core `SecretString`).
- Extra actions beyond the spec's list: ShowGenerator, CloseGenerator, ToggleGeneratorPanel, SetGeneratorMode,
  ToggleGeneratedReveal. Options and mode persist for the session; the value does not.
- The value is dropped on: discard, use, CloseGenerator, closing the side panel, dropping/saving the draft,
  ShowSettings from the generator screen, any failed GenerateNow (and before each new one), and lock.
- Actions are not screen-gated (only a session is needed); the "Use this" button is shown only when a draft is open.
  UseGenerated/CopyGenerated with nothing to use/copy give UiError::NoSelection.
- Invalid options surface the core's InvalidInput message through `UiError::Core`.
- Number fields are DragValues (length/words up to 1024) so out-of-range values can be entered and rejected by the core.
- The source-scan test (`source_has_no_random_source`) skips `SystemTime` only in clock.rs (UI clock).
