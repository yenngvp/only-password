//! Browse, search, detail and reveal state (REQ-GUI-010..012, REQ-GUI-030..032).

use std::collections::BTreeSet;
use std::fmt;

use onlypassword_core::{ItemId, ItemKind, StoredItem, Vault};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::totp::{totp_view, TotpView};
use super::{Action, AppState, Screen, Session};

/// A masked field of the detail screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldRef {
    Password,
    Notes,
    TotpSecret,
    /// The current TOTP code (never revealable: it is shown in the clear).
    TotpCode,
    /// Index into the item's custom fields.
    Custom(usize),
}

/// One list row, copied from the index: no password, notes, TOTP secret or field value.
pub struct Row {
    pub kind: ItemKind,
    pub title: String,
    pub username: Option<String>,
    pub id: ItemId,
}

impl Zeroize for Row {
    fn zeroize(&mut self) {
        self.title.zeroize();
        if let Some(u) = &mut self.username {
            u.zeroize();
        }
        self.username = None;
        self.id.0.zeroize();
        self.kind = ItemKind::Login;
    }
}

impl Drop for Row {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Row {}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Row { .. }")
    }
}

/// The open detail item. `Debug` is redacted.
pub struct Detail(pub StoredItem);

impl fmt::Debug for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Detail { .. }")
    }
}

impl Detail {
    /// The text of a field, if the item has it.
    fn field_text(&self, f: FieldRef) -> Option<&str> {
        let item = &self.0.item;
        match f {
            FieldRef::Password => item.password.as_ref().map(|p| p.expose()),
            FieldRef::Notes => Some(item.notes.expose()),
            FieldRef::TotpSecret => item.totp.as_ref().map(|t| t.secret.expose()),
            FieldRef::TotpCode => None,
            FieldRef::Custom(i) => item.fields.get(i).map(|c| c.value.expose()),
        }
    }
}

/// Browse-related part of the session. Dropping it zeroizes the rows and the search text.
#[derive(Default)]
pub(super) struct BrowseState {
    pub rows: Vec<Row>,
    pub search: Zeroizing<String>,
    pub detail: Option<Detail>,
    pub reveal: BTreeSet<FieldRef>,
    pub totp: Option<TotpView>,
    pub draft: Option<super::edit::Draft>,
    pub pending_delete: bool,
}

impl fmt::Debug for BrowseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrowseState { .. }")
    }
}

impl BrowseState {
    /// Rebuild the rows from the vault index for the current search text.
    pub(super) fn refresh(&mut self, vault: &Vault) {
        let index = vault.index();
        let found = index.search(&self.search);
        let rows = found
            .into_iter()
            .map(|s| Row {
                kind: s.kind,
                title: s.title.clone(),
                username: s.username.clone(),
                id: s.id.clone(),
            })
            .collect();
        self.rows = rows;
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session { .. }")
    }
}

impl Session {
    pub(super) fn new(vault: Vault, key: onlypassword_core::crypto::keys::SecretKey) -> Session {
        let mut browse = BrowseState::default();
        browse.refresh(&vault);
        Session { vault, key, browse }
    }

    /// Rows after any change to the vault. Drops a detail whose item is gone.
    pub(super) fn refresh_rows(&mut self) {
        self.browse.refresh(&self.vault);
        if let Some(d) = &self.browse.detail {
            if self.vault.get(&d.0.id).is_err() {
                self.browse.detail = None;
                self.browse.totp = None;
                self.browse.reveal.clear();
            }
        }
    }
}

impl AppState {
    /// The rows of the browse list (same order as `Vault::list`, filtered by the search).
    pub fn rows(&self) -> &[Row] {
        self.session.as_ref().map_or(&[], |s| &s.browse.rows)
    }

    pub fn search_text(&self) -> &str {
        self.session.as_ref().map_or("", |s| &s.browse.search)
    }

    /// The item shown on the detail screen.
    pub fn selected(&self) -> Option<&StoredItem> {
        self.session
            .as_ref()
            .and_then(|s| s.browse.detail.as_ref())
            .map(|d| &d.0)
    }

    /// The TOTP code and countdown of the open item, if it has a TOTP configuration.
    pub fn totp(&self) -> Option<&TotpView> {
        self.session.as_ref().and_then(|s| s.browse.totp.as_ref())
    }

    /// Recompute the TOTP view from the held item and the clock.
    pub(super) fn refresh_totp(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let unix = self.deps.clock.unix_secs();
        let view = session
            .browse
            .detail
            .as_ref()
            .and_then(|d| d.0.item.totp.as_ref())
            .map(|c| totp_view(c, unix));
        session.browse.totp = view;
    }

    pub fn revealed(&self) -> Option<&BTreeSet<FieldRef>> {
        self.session.as_ref().map(|s| &s.browse.reveal)
    }

    pub fn is_revealed(&self, f: FieldRef) -> bool {
        self.revealed().is_some_and(|r| r.contains(&f))
    }

    pub(super) fn browse_action(&mut self, action: Action) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match action {
            Action::Copy(f) => {
                if !matches!(self.screen, Screen::Detail(_)) {
                    return;
                }
                let Some(d) = &session.browse.detail else {
                    return;
                };
                let text = if f == FieldRef::TotpCode {
                    session
                        .browse
                        .totp
                        .as_ref()
                        .and_then(|t| t.code.as_ref())
                        .map(|c| c.as_str())
                } else {
                    d.field_text(f)
                };
                let Some(text) = text else {
                    return;
                };
                let now = self.deps.clock.now();
                if let Err(e) = self.clipboard.copy(text, now) {
                    self.notice = Some(e);
                }
            }
            Action::Search(text) => {
                if self.screen != Screen::Browse {
                    return;
                }
                session.browse.search = Zeroizing::new(text);
                session.refresh_rows();
            }
            Action::Select(id) => {
                if !matches!(self.screen, Screen::Browse | Screen::Detail(_)) {
                    return;
                }
                session.browse.reveal.clear();
                session.browse.pending_delete = false;
                match session.vault.get(&id) {
                    Ok(item) => {
                        session.browse.detail = Some(Detail(item));
                        session.browse.totp = None;
                        self.refresh_totp();
                        self.screen = Screen::Detail(id);
                    }
                    Err(e) => {
                        session.browse.detail = None;
                        session.browse.totp = None;
                        self.screen = Screen::Browse;
                        self.notice = Some(e.into());
                    }
                }
            }
            Action::ToggleReveal(f) => {
                if !matches!(self.screen, Screen::Detail(_)) {
                    return;
                }
                let Some(d) = &session.browse.detail else {
                    return;
                };
                let valid = match f {
                    FieldRef::Password => d.0.item.password.is_some(),
                    FieldRef::Notes => true,
                    FieldRef::TotpSecret => d.0.item.totp.is_some(),
                    FieldRef::TotpCode => false,
                    FieldRef::Custom(i) => d.0.item.fields.get(i).is_some_and(|c| c.hidden),
                };
                if valid && !session.browse.reveal.remove(&f) {
                    session.browse.reveal.insert(f);
                }
            }
            Action::Back => {
                if matches!(self.screen, Screen::Detail(_)) {
                    session.browse.detail = None;
                    session.browse.totp = None;
                    session.browse.reveal.clear();
                    session.browse.pending_delete = false;
                    self.screen = Screen::Browse;
                }
            }
            _ => {}
        }
    }
}
