//! In-memory item index for list views (architecture.md §7.1, REQ-IDX-001..003).

use super::ItemSummary;
use zeroize::Zeroize;

/// Summaries of every item, sorted exactly as `Vault::list`. Holds no password, notes, TOTP
/// secret or custom-field value. `Debug` is a fixed string; every owned string is zeroized
/// on drop.
pub struct ItemIndex {
    entries: Vec<ItemSummary>,
}

impl std::fmt::Debug for ItemIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemIndex { .. }")
    }
}

fn sort_key(s: &ItemSummary) -> (String, [u8; 16]) {
    (s.title.to_lowercase(), s.id.0)
}

impl ItemIndex {
    pub(super) fn empty() -> ItemIndex {
        ItemIndex {
            entries: Vec::new(),
        }
    }

    pub(super) fn from_summaries(mut entries: Vec<ItemSummary>) -> ItemIndex {
        entries.sort_by_cached_key(sort_key);
        ItemIndex { entries }
    }

    /// A new index equal to this one with `summary` added or replacing the same id.
    pub(super) fn with(&self, summary: ItemSummary) -> ItemIndex {
        let mut v: Vec<ItemSummary> = self
            .entries
            .iter()
            .filter(|e| e.id != summary.id)
            .cloned()
            .collect();
        v.push(summary);
        Self::from_summaries(v)
    }

    /// A new index equal to this one without the item `id`.
    pub(super) fn without(&self, id: &crate::item::ItemId) -> ItemIndex {
        ItemIndex {
            entries: self
                .entries
                .iter()
                .filter(|e| e.id != *id)
                .cloned()
                .collect(),
        }
    }

    /// A new index with `extra` summaries added.
    pub(super) fn with_all(&self, extra: Vec<ItemSummary>) -> ItemIndex {
        let mut v = self.entries.clone();
        v.extend(extra);
        Self::from_summaries(v)
    }

    /// All summaries in `Vault::list` order.
    pub fn entries(&self) -> &[ItemSummary] {
        &self.entries
    }

    /// Same rule and order as `Vault::search` (REQ-LIF-009); decrypts nothing.
    pub fn search(&self, query: &str) -> Vec<&ItemSummary> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|s| {
                s.title.to_lowercase().contains(q.as_str())
                    || s.username
                        .as_ref()
                        .is_some_and(|u| u.to_lowercase().contains(q.as_str()))
                    || s.urls.iter().any(|u| u.to_lowercase().contains(q.as_str()))
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ItemIndex {
    /// Zeroizes every owned string in place.
    pub(super) fn wipe_strings(&mut self) {
        for s in &mut self.entries {
            s.title.zeroize();
            if let Some(u) = &mut s.username {
                u.zeroize();
            }
            for u in &mut s.urls {
                u.zeroize();
            }
        }
    }
}

impl Drop for ItemIndex {
    fn drop(&mut self) {
        self.wipe_strings();
        self.entries.clear();
    }
}
