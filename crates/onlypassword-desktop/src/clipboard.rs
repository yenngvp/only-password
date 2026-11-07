//! Clipboard service with a timed clear (architecture.md 7.4).
//!
//! The copied text exists here only as the argument of the backend call; the
//! service remembers a SHA-256 digest and a deadline.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::UiError;

/// What the service needs from a clipboard. Errors carry no detail.
#[allow(clippy::result_unit_err)]
pub trait ClipboardBackend {
    /// The current text, or `None` when the clipboard holds no text.
    fn get_text(&mut self) -> Result<Option<String>, ()>;
    /// Place text on the clipboard, marked sensitive where the platform allows.
    fn set_secret_text(&mut self, text: &str) -> Result<(), ()>;
    fn clear(&mut self) -> Result<(), ()>;
}

/// The real clipboard (arboard). Never used in tests.
pub struct ArboardBackend {
    inner: Option<arboard::Clipboard>,
}

impl ArboardBackend {
    pub fn new() -> Self {
        ArboardBackend { inner: None }
    }

    /// Connect lazily so that a missing display only fails a copy.
    fn clipboard(&mut self) -> Result<&mut arboard::Clipboard, ()> {
        if self.inner.is_none() {
            self.inner = Some(arboard::Clipboard::new().map_err(|_| ())?);
        }
        self.inner.as_mut().ok_or(())
    }
}

impl Default for ArboardBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ArboardBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArboardBackend { .. }")
    }
}

impl ClipboardBackend for ArboardBackend {
    fn get_text(&mut self) -> Result<Option<String>, ()> {
        match self.clipboard()?.get_text() {
            Ok(t) => Ok(Some(t)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(_) => Err(()),
        }
    }

    fn set_secret_text(&mut self, text: &str) -> Result<(), ()> {
        let cb = self.clipboard()?;
        let set = cb.set();
        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history().exclude_from_cloud()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        // arboard 3.7 has no history exclusion on Linux/X11/Wayland: plain set.
        set.text(text).map_err(|_| ())
    }

    fn clear(&mut self) -> Result<(), ()> {
        self.clipboard()?.clear().map_err(|_| ())
    }
}

#[derive(Debug, Default)]
struct MemInner {
    text: Option<String>,
    sensitive: bool,
    fail: bool,
    reads: usize,
    sets: usize,
    clears: usize,
}

/// In-memory clipboard for tests. Clones share the same state.
#[derive(Debug, Clone, Default)]
pub struct MemoryClipboard {
    inner: Arc<Mutex<MemInner>>,
}

impl MemoryClipboard {
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(&self) -> MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current text without counting as a service read.
    pub fn text(&self) -> Option<String> {
        self.guard().text.clone()
    }

    /// The `sensitive` flag of the last set.
    pub fn sensitive(&self) -> bool {
        self.guard().sensitive
    }

    /// Make every backend call fail (or work again).
    pub fn set_failing(&self, fail: bool) {
        self.guard().fail = fail;
    }

    /// Put text on the clipboard as another application would (not sensitive).
    pub fn set_external(&self, text: &str) {
        let mut g = self.guard();
        g.text = Some(text.to_owned());
        g.sensitive = false;
    }

    pub fn reads(&self) -> usize {
        self.guard().reads
    }

    pub fn sets(&self) -> usize {
        self.guard().sets
    }

    pub fn clears(&self) -> usize {
        self.guard().clears
    }
}

impl ClipboardBackend for MemoryClipboard {
    fn get_text(&mut self) -> Result<Option<String>, ()> {
        let mut g = self.guard();
        g.reads += 1;
        if g.fail {
            return Err(());
        }
        Ok(g.text.clone())
    }

    fn set_secret_text(&mut self, text: &str) -> Result<(), ()> {
        let mut g = self.guard();
        if g.fail {
            return Err(());
        }
        g.sets += 1;
        g.text = Some(text.to_owned());
        g.sensitive = true;
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ()> {
        let mut g = self.guard();
        if g.fail {
            return Err(());
        }
        g.clears += 1;
        g.text = None;
        g.sensitive = false;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Pending {
    digest: [u8; 32],
    deadline: Duration,
}

/// Copy with a timed clear. `Debug` shows only whether a clear is pending.
pub struct ClipboardService {
    backend: Box<dyn ClipboardBackend>,
    timeout: Duration,
    pending: Option<Pending>,
}

impl fmt::Debug for ClipboardService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardService")
            .field("timeout", &self.timeout)
            .field("pending", &self.pending.is_some())
            .finish()
    }
}

fn digest_of(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

impl ClipboardService {
    pub fn new(backend: Box<dyn ClipboardBackend>, timeout: Duration) -> Self {
        ClipboardService {
            backend,
            timeout,
            pending: None,
        }
    }

    /// Change the timeout for later copies; a pending deadline is not moved.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// True when no clear is pending.
    pub fn is_clean(&self) -> bool {
        self.pending.is_none()
    }

    /// Place `text` on the clipboard and arm the clear. On failure nothing
    /// changes (an earlier pending clear stays).
    pub fn copy(&mut self, text: &str, now: Duration) -> Result<(), UiError> {
        self.backend
            .set_secret_text(text)
            .map_err(|()| UiError::Clipboard)?;
        self.pending = Some(Pending {
            digest: digest_of(text),
            deadline: now.saturating_add(self.timeout),
        });
        Ok(())
    }

    /// Clear if the deadline has passed and the clipboard still holds our value.
    pub fn poll(&mut self, now: Duration) -> Result<(), UiError> {
        match self.pending {
            Some(p) if now >= p.deadline => self.clear_if_ours(),
            _ => Ok(()),
        }
    }

    /// The same clear without waiting for the deadline (lock, exit).
    pub fn clear_now(&mut self) -> Result<(), UiError> {
        self.clear_if_ours()
    }

    fn clear_if_ours(&mut self) -> Result<(), UiError> {
        let Some(p) = self.pending.take() else {
            return Ok(());
        };
        match self.backend.get_text() {
            Ok(Some(t)) if digest_of(&t) == p.digest => {
                self.backend.clear().map_err(|()| UiError::Clipboard)
            }
            Ok(_) => Ok(()),
            Err(()) => Err(UiError::Clipboard),
        }
    }
}
