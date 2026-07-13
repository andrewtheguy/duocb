//! Global keyboard shortcuts, fed by the window's root `FocusScope`.
//!
//! Plain letter keys are only bound while no text field has focus, so typing
//! is never hijacked; elsewhere shortcuts require the platform command
//! modifier. Slint normalizes that modifier into `control` (Command on macOS,
//! Ctrl on Windows/Linux), matching the previous toolkit's COMMAND semantics.
//! Escape with a focused field never reaches this handler — the window's
//! focus scope uses it to release the focus first.

use slint::platform::Key;

use super::App;
use crate::{ConfigureStep, PairMode, PinChannel, Screen};
use duocb_core::net::ConnStatus;

/// Handle one key event. `plain` = no modifier held at all; `command` =
/// exactly the platform command modifier — extra modifiers disqualify a
/// shortcut in both cases (parity with the previous toolkit's exact-modifier
/// matching, so e.g. Shift+S or Ctrl+Enter never fire the plain shortcuts).
/// Returns whether the key was consumed (so the caller can accept it and
/// nothing double-fires).
pub(crate) fn handle_global_key(
    app: &mut App,
    text: &str,
    plain: bool,
    command: bool,
    field_focused: bool,
) -> bool {
    let focus_free = !field_focused;
    let key = text.chars().next();
    let esc = plain && key == Some(char::from(Key::Escape));
    let enter = plain && key == Some(char::from(Key::Return));
    let up = plain && key == Some(char::from(Key::UpArrow));
    let down = plain && key == Some(char::from(Key::DownArrow));
    let command_enter = command && key == Some(char::from(Key::Return));
    // A plain (unmodified) letter shortcut.
    let letter = |c: char| plain && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));
    // A command-modified letter shortcut.
    let command = |c: char| command && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));

    if focus_free && app.screen != Screen::Home && esc {
        app.go_back();
        return true;
    }

    let handled = match app.screen {
        Screen::Home if focus_free => handle_configure_key(app, esc, enter, up, down, &letter, &command),
        Screen::Quick if focus_free => {
            // Each letter/number picks a whole pairing preset (mode + channel),
            // matching the rows on screen: P and L are the common choices; 2 and
            // M are the uncommon (testing) ones, which the UI reveals when
            // selected. Selecting one keeps quick mode out of configure mode.
            if letter('p') {
                app.mode = PairMode::NostrPin;
                app.pin_channel = PinChannel::Both;
            } else if letter('l') {
                app.mode = PairMode::NostrPin;
                app.pin_channel = PinChannel::LanOnly;
            } else if letter('i') {
                app.mode = PairMode::NostrPin;
                app.pin_channel = PinChannel::NostrOnly;
            } else if letter('m') {
                app.mode = PairMode::Manual;
            } else if letter('s') {
                app.begin_server();
            } else if letter('c') {
                app.screen = Screen::Client;
            } else {
                return handle_session_key(app, focus_free, &command);
            }
            true
        }
        Screen::Server => {
            // Copy the displayed credential without the mouse: the pairing code
            // (manual mode) or the current rotating PIN (PIN mode).
            if command('t') && app.pairing_code.is_some() {
                let code = app.pairing_code.clone().unwrap();
                app.copy_to_clipboard(&code);
                true
            } else if command('t') && app.pin_display.is_some() {
                let pin = app.pin_display.clone().unwrap();
                app.copy_to_clipboard(&pin);
                true
            } else {
                false
            }
        }
        Screen::Client => {
            if !app.client_active && command_enter {
                app.connect_client();
                true
            } else {
                false
            }
        }
        _ => false,
    };
    if handled {
        return true;
    }

    handle_session_key(app, focus_free, &command)
}

/// Configure-mode home shortcuts, per wizard/hub step. Only called with no
/// text field focused.
fn handle_configure_key(
    app: &mut App,
    esc: bool,
    enter: bool,
    up: bool,
    down: bool,
    letter: &dyn Fn(char) -> bool,
    command: &dyn Fn(char) -> bool,
) -> bool {
    if letter('q') {
        app.open_quick();
        return true;
    }
    match app.configure_step {
        ConfigureStep::SetupChoice => {
            if letter('g') {
                app.begin_generate_secret();
            } else if letter('i') {
                app.configure_step = ConfigureStep::SetupImport;
            } else {
                return false;
            }
            true
        }
        ConfigureStep::SetupImport => {
            if esc {
                app.cancel_setup();
                true
            } else {
                false
            }
        }
        ConfigureStep::SetupName => {
            if esc && app.has_saved_identity() {
                app.cancel_name();
                true
            } else {
                false
            }
        }
        ConfigureStep::Ready => {
            if letter('s') {
                app.begin_server();
            } else if letter('c') {
                app.enter_join_picker();
            } else if command('t') && app.secret.is_some() {
                let secret = app.secret.clone().unwrap();
                app.copy_secret_to_clipboard(&secret);
            } else {
                return false;
            }
            true
        }
        ConfigureStep::Join => {
            if letter('c') || enter {
                app.join_selected_peer();
            } else if letter('r') {
                app.refresh_peers();
            } else if down {
                app.move_peer_selection(1);
            } else if up {
                app.move_peer_selection(-1);
            } else if esc {
                app.configure_step = ConfigureStep::Ready;
            } else {
                return false;
            }
            true
        }
    }
}

/// Shortcuts for a live paired session (any screen). Gated on no text field
/// having focus so field-editing shortcuts and destructive actions (clear
/// inbox) can't fire while typing.
fn handle_session_key(app: &mut App, focus_free: bool, command: &dyn Fn(char) -> bool) -> bool {
    if app.status != ConnStatus::Connected || !focus_free {
        return false;
    }
    if command('s') {
        app.send_clipboard();
    } else if command('p') {
        if let Some(item) = app.inbox.first_mut() {
            item.toggle_peek();
        }
    } else if command('y') {
        // Ctrl/Command+Y ("yank") instead of the platform Copy shortcut, which
        // belongs to the focused text widgets.
        if let Some(text) = app.inbox.first().map(|i| i.text.clone()) {
            app.copy_to_clipboard(&text);
        }
    } else if command('l') {
        app.inbox.clear();
    } else {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::test_app;

    const ESC: &str = "\u{1b}";

    /// A key with no modifiers held.
    fn plain(app: &mut App, text: &str, field_focused: bool) -> bool {
        handle_global_key(app, text, true, false, field_focused)
    }

    /// A key with exactly the command modifier held.
    fn command(app: &mut App, text: &str, field_focused: bool) -> bool {
        handle_global_key(app, text, false, true, field_focused)
    }

    #[test]
    fn quick_screen_letters_route() {
        let mut app = test_app();
        app.open_quick();
        assert_eq!(app.mode, PairMode::NostrPin);
        // Each key selects a whole preset (mode + channel).
        assert!(plain(&mut app, "l", false));
        assert_eq!(app.mode, PairMode::NostrPin);
        assert_eq!(app.pin_channel, PinChannel::LanOnly);
        // The uncommon "internet only" preset, and it auto-reveals the section.
        assert!(plain(&mut app, "i", false));
        assert_eq!(app.pin_channel, PinChannel::NostrOnly);
        assert!(app.quick_advanced_open());
        // Back to the default PIN preset closes the uncommon section again.
        assert!(plain(&mut app, "p", false));
        assert_eq!(app.mode, PairMode::NostrPin);
        assert_eq!(app.pin_channel, PinChannel::Both);
        assert!(!app.quick_advanced_open());
        assert!(plain(&mut app, "m", false));
        assert_eq!(app.mode, PairMode::Manual);
        assert!(app.quick_advanced_open());
        assert!(plain(&mut app, "c", false));
        assert_eq!(app.screen, Screen::Client);
        assert!(plain(&mut app, ESC, false));
        assert_eq!(app.screen, Screen::Quick);
    }

    #[test]
    fn letters_ignored_while_field_focused() {
        let mut app = test_app();
        app.open_quick();
        assert!(!plain(&mut app, "m", true));
        assert_eq!(app.mode, PairMode::NostrPin);
    }

    #[test]
    fn wizard_keys_route() {
        let mut app = test_app();
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        // Generate persists the secret and jumps straight to naming — no
        // intermediate "save the secret" step.
        assert!(plain(&mut app, "g", false));
        assert_eq!(app.configure_step, ConfigureStep::SetupName);
        assert!(app.secret.is_some());
        // Import opens the paste step, and Esc backs out to the choice.
        app.clear_secret();
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        assert!(plain(&mut app, "i", false));
        assert_eq!(app.configure_step, ConfigureStep::SetupImport);
        assert!(plain(&mut app, ESC, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
    }

    #[test]
    fn modified_keys_do_not_trigger_plain_shortcuts() {
        let mut app = test_app();
        // ⌘G on the setup choice must not start generating…
        assert!(!command(&mut app, "g", false));
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        // …and neither may a letter with any other modifier (plain=false,
        // command=false — e.g. Shift or Alt held).
        assert!(!handle_global_key(&mut app, "G", false, false, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        // Modified Esc must not navigate either.
        app.open_quick();
        assert!(!handle_global_key(&mut app, ESC, false, false, false));
        assert_eq!(app.screen, Screen::Quick);
        // And ⌘Enter in the join picker must not join.
        app.screen = Screen::Home;
        app.mode = PairMode::NostrToken;
        app.configure_step = ConfigureStep::Join;
        let enter = char::from(Key::Return).to_string();
        assert!(!command(&mut app, &enter, false));
    }

    #[test]
    fn join_picker_arrows_and_escape() {
        let mut app = test_app();
        app.configure_step = ConfigureStep::Join;
        app.peers = vec![crate::app::tests::peer("a", "s1")];
        let down = char::from(Key::DownArrow).to_string();
        assert!(plain(&mut app, &down, false));
        assert_eq!(app.selected_peer.as_deref(), Some("s1"));
        assert!(plain(&mut app, ESC, false));
        assert_eq!(app.configure_step, ConfigureStep::Ready);
    }
}
