//! Add, edit and delete items (REQ-GUI-020..023, REQ-GUI-033).

use std::collections::BTreeSet;
use std::fmt;

use onlypassword_core::base32::normalize_totp_secret;
use onlypassword_core::{CustomField, Item, ItemKind, SecretString, TotpAlgorithm, TotpConfig};

use super::browse::Detail;
use super::{Action, AppState, FieldRef, Screen};
use crate::secret_buf::SecretBuf;

/// One custom field of a draft. Values are always held in a `SecretBuf`;
/// the view masks them only when `hidden` is set.
#[derive(Default)]
pub struct DraftField {
    pub name: String,
    pub value: SecretBuf,
    pub hidden: bool,
}

/// The item being added or edited. Secrets live in `SecretBuf`s, which
/// zeroize on drop. `Debug` is redacted.
pub struct Draft {
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub password: SecretBuf,
    pub notes: SecretBuf,
    pub totp_secret: SecretBuf,
    pub totp_algorithm: TotpAlgorithm,
    pub totp_digits: u8,
    pub totp_period: u32,
    pub fields: Vec<DraftField>,
    /// Secret fields currently shown in the clear in the form.
    pub revealed: BTreeSet<FieldRef>,
}

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Draft { .. }")
    }
}

impl Draft {
    fn new(kind: ItemKind) -> Draft {
        Draft {
            kind,
            title: String::new(),
            username: String::new(),
            urls: Vec::new(),
            password: SecretBuf::new(),
            notes: SecretBuf::new(),
            totp_secret: SecretBuf::new(),
            totp_algorithm: TotpAlgorithm::Sha1,
            totp_digits: 6,
            totp_period: 30,
            fields: Vec::new(),
            revealed: BTreeSet::new(),
        }
    }

    fn from_item(item: &Item) -> Draft {
        let mut d = Draft::new(item.kind);
        d.title = item.title.clone();
        d.username = item.username.clone().unwrap_or_default();
        d.urls = item.urls.clone();
        if let Some(p) = &item.password {
            d.password.push_str(p.expose());
        }
        d.notes.push_str(item.notes.expose());
        if let Some(t) = &item.totp {
            d.totp_secret.push_str(t.secret.expose());
            d.totp_algorithm = t.algorithm;
            d.totp_digits = t.digits;
            d.totp_period = t.period;
        }
        for c in &item.fields {
            let mut value = SecretBuf::new();
            value.push_str(c.value.expose());
            d.fields.push(DraftField {
                name: c.name.clone(),
                value,
                hidden: c.hidden,
            });
        }
        d
    }

    /// Build the core item. Notes drafts take only title and notes; empty
    /// optional login fields become `None`.
    fn to_item(&self) -> onlypassword_core::Result<Item> {
        let notes = SecretString::new(self.notes.expose().to_owned());
        if self.kind == ItemKind::Note {
            return Ok(Item::new_note(self.title.clone(), notes));
        }
        let mut item = Item::new_login(self.title.clone());
        item.username = non_empty(&self.username);
        item.password = (!self.password.is_empty())
            .then(|| SecretString::new(self.password.expose().to_owned()));
        item.urls = self.urls.clone();
        item.notes = notes;
        if !self.totp_secret.is_empty() {
            item.totp = Some(TotpConfig {
                secret: normalize_totp_secret(self.totp_secret.expose())?,
                algorithm: self.totp_algorithm,
                digits: self.totp_digits,
                period: self.totp_period,
            });
        }
        item.fields = self
            .fields
            .iter()
            .map(|f| CustomField {
                name: f.name.clone(),
                value: SecretString::new(f.value.expose().to_owned()),
                hidden: f.hidden,
            })
            .collect();
        Ok(item)
    }
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

impl AppState {
    /// The open draft, if the edit screen is shown.
    pub fn draft(&self) -> Option<&Draft> {
        self.session.as_ref().and_then(|s| s.browse.draft.as_ref())
    }

    /// Direct access to the draft buffers (secret fields are typed into them by the view).
    pub fn draft_mut(&mut self) -> Option<&mut Draft> {
        self.session.as_mut().and_then(|s| s.browse.draft.as_mut())
    }

    /// True while the delete confirmation is shown.
    pub fn delete_pending(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.browse.pending_delete)
    }

    /// Drop the draft and the delete confirmation. Returns to the browse or
    /// detail screen when the edit screen was shown.
    pub(super) fn drop_draft(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.browse.draft = None;
            s.browse.pending_delete = false;
        }
        self.close_generator_panel();
        self.wipe_requested = true;
        if let Screen::Edit(id) = &self.screen {
            let has_detail = self
                .session
                .as_ref()
                .is_some_and(|s| s.browse.detail.is_some());
            self.screen = match id {
                Some(id) if has_detail => Screen::Detail(id.clone()),
                _ => Screen::Browse,
            };
        }
    }

    pub(super) fn edit_action(&mut self, action: Action) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match action {
            Action::BeginAdd(kind) => {
                if self.screen != Screen::Browse {
                    return;
                }
                session.browse.draft = Some(Draft::new(kind));
                self.screen = Screen::Edit(None);
            }
            Action::BeginEdit => {
                let Screen::Detail(id) = &self.screen else {
                    return;
                };
                let Some(d) = &session.browse.detail else {
                    return;
                };
                let draft = Draft::from_item(&d.0.item);
                session.browse.draft = Some(draft);
                session.browse.reveal.clear();
                session.browse.pending_delete = false;
                self.screen = Screen::Edit(Some(id.clone()));
            }
            Action::SaveDraft => self.save_draft(),
            Action::CancelDraft => {
                if matches!(self.screen, Screen::Edit(_)) {
                    self.drop_draft();
                }
            }
            Action::RequestDelete => {
                if matches!(self.screen, Screen::Detail(_)) && session.browse.detail.is_some() {
                    session.browse.pending_delete = true;
                }
            }
            Action::CancelDelete => session.browse.pending_delete = false,
            Action::ConfirmDelete => self.confirm_delete(),
            other => self.edit_setter(other),
        }
    }

    fn edit_setter(&mut self, action: Action) {
        if !matches!(self.screen, Screen::Edit(_)) {
            return;
        }
        let Some(d) = self.draft_mut() else {
            return;
        };
        match action {
            Action::SetKind(k) => d.kind = k,
            Action::SetTitle(t) => d.title = t,
            Action::SetUsername(u) => d.username = u,
            Action::SetUrl(i, u) => {
                if let Some(slot) = d.urls.get_mut(i) {
                    *slot = u;
                }
            }
            Action::AddUrl => d.urls.push(String::new()),
            Action::RemoveUrl(i) => {
                if i < d.urls.len() {
                    d.urls.remove(i);
                }
            }
            Action::SetTotpAlgorithm(a) => d.totp_algorithm = a,
            Action::SetTotpDigits(n) => d.totp_digits = n,
            Action::SetTotpPeriod(n) => d.totp_period = n,
            Action::AddField => d.fields.push(DraftField::default()),
            Action::RemoveField(i) => {
                if i < d.fields.len() {
                    d.fields.remove(i);
                    d.revealed.retain(|f| !matches!(f, FieldRef::Custom(_)));
                }
            }
            Action::SetFieldName(i, n) => {
                if let Some(f) = d.fields.get_mut(i) {
                    f.name = n;
                }
            }
            Action::SetFieldHidden(i, h) => {
                if let Some(f) = d.fields.get_mut(i) {
                    f.hidden = h;
                    if !h {
                        d.revealed.remove(&FieldRef::Custom(i));
                    }
                }
            }
            Action::ToggleDraftReveal(f) if !d.revealed.remove(&f) => {
                d.revealed.insert(f);
            }
            _ => {}
        }
    }

    fn save_draft(&mut self) {
        let Screen::Edit(target) = self.screen.clone() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(draft) = &session.browse.draft else {
            return;
        };
        let result = draft.to_item().and_then(|item| match &target {
            Some(id) => session.vault.update(id, &item).map(|()| id.clone()),
            None => session.vault.add(&item),
        });
        match result {
            Ok(id) => {
                session.browse.draft = None;
                session.browse.generator.close();
                session.browse.pending_delete = false;
                session.browse.reveal.clear();
                session.refresh_rows();
                self.wipe_requested = true;
                match session.vault.get(&id) {
                    Ok(item) => {
                        session.browse.detail = Some(Detail(item));
                        self.screen = Screen::Detail(id);
                        self.refresh_totp();
                    }
                    Err(e) => {
                        session.browse.detail = None;
                        self.screen = Screen::Browse;
                        self.notice = Some(e.into());
                    }
                }
            }
            Err(e) => self.notice = Some(e.into()),
        }
    }

    fn confirm_delete(&mut self) {
        let Screen::Detail(id) = self.screen.clone() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if !session.browse.pending_delete {
            return;
        }
        session.browse.pending_delete = false;
        match session.vault.delete(&id) {
            Ok(()) => {
                session.browse.detail = None;
                session.browse.totp = None;
                session.browse.reveal.clear();
                session.refresh_rows();
                self.screen = Screen::Browse;
                self.wipe_requested = true;
            }
            Err(e) => self.notice = Some(e.into()),
        }
    }
}
