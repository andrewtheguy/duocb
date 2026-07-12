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
use crate::{ConfigureStep, PairMode, Screen};
use duocb_core::net::ConnStatus;

/// Handle one key event. Returns whether the key was consumed (so the caller
/// can accept it and nothing double-fires).
pub(crate) fn handle_global_key(
    app: &mut App,
    text: &str,
    control: bool,
    field_focused: bool,
) -> bool {
    let focus_free = !field_focused;
    let key = text.chars().next();
    let esc = key == Some(char::from(Key::Escape));
    let enter = key == Some(char::from(Key::Return));
    let up = key == Some(char::from(Key::UpArrow));
    let down = key == Some(char::from(Key::DownArrow));
    // A plain (unmodified) letter shortcut.
    let letter = |c: char| !control && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));
    // A command-modified letter shortcut.
    let command = |c: char| control && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));

    if focus_free && app.screen != Screen::Home && esc && !control {
        app.go_back();
        return true;
    }

    let handled = match app.screen {
        Screen::Home if focus_free => handle_configure_key(app, esc, enter, up, down, &letter, &command),
        Screen::Quick if focus_free => {
            if letter('p') {
                app.mode = PairMode::NostrPin;
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
            // Copy displayed initiator credentials without the mouse.
            if command('i') && app.node_id.is_some() {
                let node_id = app.node_id.clone().unwrap();
                app.copy_to_clipboard(&node_id);
                true
            } else if command('t') && app.manual_token.is_some() {
                let token = app.manual_token.clone().unwrap();
                app.copy_to_clipboard(&token);
                true
            } else {
                false
            }
        }
        Screen::Client => {
            if !app.client_active && control && enter {
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
        ConfigureStep::SetupGenerate | ConfigureStep::SetupImport => {
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

    #[test]
    fn quick_screen_letters_route() {
        let mut app = test_app();
        app.open_quick();
        assert!(handle_global_key(&mut app, "m", false, false));
        assert_eq!(app.mode, PairMode::Manual);
        assert!(handle_global_key(&mut app, "c", false, false));
        assert_eq!(app.screen, Screen::Client);
        assert!(handle_global_key(&mut app, ESC, false, false));
        assert_eq!(app.screen, Screen::Quick);
    }

    #[test]
    fn letters_ignored_while_field_focused() {
        let mut app = test_app();
        app.open_quick();
        assert!(!handle_global_key(&mut app, "m", false, true));
        assert_eq!(app.mode, PairMode::NostrPin);
    }

    #[test]
    fn wizard_keys_route() {
        let mut app = test_app();
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        assert!(handle_global_key(&mut app, "g", false, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupGenerate);
        assert!(handle_global_key(&mut app, ESC, false, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
        assert!(handle_global_key(&mut app, "i", false, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupImport);
    }

    #[test]
    fn command_letters_do_not_trigger_plain_shortcuts() {
        let mut app = test_app();
        // ⌘G on the setup choice must not start generating.
        assert!(!handle_global_key(&mut app, "g", true, false));
        assert_eq!(app.configure_step, ConfigureStep::SetupChoice);
    }

    #[test]
    fn join_picker_arrows_and_escape() {
        let mut app = test_app();
        app.configure_step = ConfigureStep::Join;
        app.peers = vec![crate::app::tests::peer("a", "s1", false)];
        let down = char::from(Key::DownArrow).to_string();
        assert!(handle_global_key(&mut app, &down, false, false));
        assert_eq!(app.selected_peer.as_deref(), Some("s1"));
        assert!(handle_global_key(&mut app, ESC, false, false));
        assert_eq!(app.configure_step, ConfigureStep::Ready);
    }
}
