//! Startup recovery for a config that will not load.
//!
//! Persisted state duocb cannot read has always been a hard stop — it must be,
//! since starting anyway would mean silently replacing an identity peers
//! already trust. What it must not be is a *silent* stop: the failure used to
//! end the process before any window existed, leaving one line of stderr, and
//! on a GUI-subsystem Windows build nothing at all.
//!
//! So the failure gets its own window instead. It names the path, shows the
//! error chain, and offers the one repair available at that point — throwing
//! the file away and starting over — so the choice to lose the identity is the
//! user's, made with the reason in front of them.

use std::cell::Cell;
use std::rc::Rc;

use anyhow::Result;
use slint::ComponentHandle as _;

use crate::ConfigRecoveryWindow;
use crate::config::{Config, ConfigLock};

/// Show `error` and act on the answer. `Ok(None)` means the user chose to quit
/// (or closed the window) and the config was left untouched — a clean exit, not
/// a failure.
///
/// A reset that fails on its own account — a credential store that cannot be
/// written, an undeletable file — puts the user back in front of the window
/// with the new error rather than crashing out of it, so quitting deliberately
/// stays available.
pub fn recover(lock: &ConfigLock, error: &anyhow::Error) -> Result<Option<Config>> {
    let mut details = format!("{error:#}");
    loop {
        if !ask(lock, &details)? {
            return Ok(None);
        }
        match lock.reset() {
            Ok(config) => return Ok(Some(config)),
            Err(e) => {
                log::error!("resetting config {}: {e:#}", lock.path().display());
                details = format!("Resetting the configuration failed.\n\n{e:#}");
            }
        }
    }
}

/// Run the recovery window to a decision: `true` to reset, `false` to quit.
/// Closing the window is a quit, so the destructive answer is never the one a
/// stray click produces.
fn ask(lock: &ConfigLock, details: &str) -> Result<bool> {
    let window = ConfigRecoveryWindow::new()?;
    let (ui_font, mono_font) = crate::platform_fonts();
    window.set_ui_font(ui_font.into());
    window.set_mono_font(mono_font.into());
    window.set_config_path(lock.path().display().to_string().into());
    window.set_backup_path(lock.broken_path().display().to_string().into());
    window.set_details(details.into());

    let reset = Rc::new(Cell::new(false));
    window.on_reset({
        let reset = Rc::clone(&reset);
        move || {
            reset.set(true);
            let _ = slint::quit_event_loop();
        }
    });
    window.on_quit(|| {
        let _ = slint::quit_event_loop();
    });

    window.run()?;
    Ok(reset.get())
}
