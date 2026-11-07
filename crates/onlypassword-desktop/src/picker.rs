//! Native file dialogs behind a trait, so tests never open a window.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Blocking file choosers. `None` means the user cancelled.
pub trait FilePicker {
    fn pick_vault(&mut self) -> Option<PathBuf>;
    fn pick_key_file(&mut self) -> Option<PathBuf>;
    fn save_vault(&mut self) -> Option<PathBuf>;
    fn save_key_file(&mut self) -> Option<PathBuf>;
    fn pick_export(&mut self) -> Option<PathBuf>;
    fn save_export(&mut self) -> Option<PathBuf>;
}

/// The real picker (rfd's blocking `FileDialog`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RfdPicker;

impl RfdPicker {
    pub fn new() -> Self {
        RfdPicker
    }

    fn open(title: &str) -> Option<PathBuf> {
        rfd::FileDialog::new().set_title(title).pick_file()
    }

    fn save(title: &str) -> Option<PathBuf> {
        rfd::FileDialog::new().set_title(title).save_file()
    }
}

impl FilePicker for RfdPicker {
    fn pick_vault(&mut self) -> Option<PathBuf> {
        Self::open("Choose vault file")
    }
    fn pick_key_file(&mut self) -> Option<PathBuf> {
        Self::open("Choose secret-key file")
    }
    fn save_vault(&mut self) -> Option<PathBuf> {
        Self::save("New vault file")
    }
    fn save_key_file(&mut self) -> Option<PathBuf> {
        Self::save("New secret-key file")
    }
    fn pick_export(&mut self) -> Option<PathBuf> {
        Self::open("Choose export file")
    }
    fn save_export(&mut self) -> Option<PathBuf> {
        Self::save("Export file")
    }
}

/// Test picker: every call pops the next queued answer (`None` when empty).
/// Clones share the queue, so a test can keep a handle after boxing one.
#[derive(Debug, Clone, Default)]
pub struct ScriptedPicker {
    answers: Arc<Mutex<VecDeque<Option<PathBuf>>>>,
}

impl ScriptedPicker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue an answer (`None` = the user cancels).
    pub fn push(&self, answer: Option<PathBuf>) {
        self.queue().push_back(answer);
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Option<PathBuf>>> {
        self.answers.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn next(&self) -> Option<PathBuf> {
        self.queue().pop_front().flatten()
    }
}

impl FilePicker for ScriptedPicker {
    fn pick_vault(&mut self) -> Option<PathBuf> {
        self.next()
    }
    fn pick_key_file(&mut self) -> Option<PathBuf> {
        self.next()
    }
    fn save_vault(&mut self) -> Option<PathBuf> {
        self.next()
    }
    fn save_key_file(&mut self) -> Option<PathBuf> {
        self.next()
    }
    fn pick_export(&mut self) -> Option<PathBuf> {
        self.next()
    }
    fn save_export(&mut self) -> Option<PathBuf> {
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_returns_queue_then_none() {
        let handle = ScriptedPicker::new();
        let mut p = handle.clone();
        handle.push(Some(PathBuf::from("a")));
        handle.push(None);
        handle.push(Some(PathBuf::from("b")));
        assert_eq!(p.pick_vault(), Some(PathBuf::from("a")));
        assert_eq!(p.pick_key_file(), None);
        assert_eq!(p.save_vault(), Some(PathBuf::from("b")));
        assert_eq!(p.save_export(), None);
    }
}
