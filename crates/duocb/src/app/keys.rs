//! Global keyboard shortcuts, fed by the window's root `FocusScope`.
//!
//! Plain letter keys are only bound while no text field has focus, so typing
//! is never hijacked; elsewhere shortcuts require the platform command
//! modifier. Slint normalizes that modifier into `control` (Command on macOS,
//! Ctrl on Windows/Linux), matching the previous toolkit's COMMAND semantics.
//! Escape with a focused field never reaches this handler — the window's
//! focus scope uses it to release the focus first.

use slint::platform::Key;

use super::{App, CopyTarget};
use crate::{ConfigureStep, Screen};
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
    // A plain (unmodified) letter shortcut.
    let letter = |c: char| plain && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));
    // A command-modified letter shortcut.
    let command = |c: char| command && key.is_some_and(|k| k.eq_ignore_ascii_case(&c));

    // A modal owns the keyboard while it is up, so Esc dismisses the modal
    // rather than navigating the screen behind it.
    if app.confirm_reset_identity {
        if enter {
            app.reset_identity();
            app.confirm_reset_identity = false;
        } else if esc {
            app.confirm_reset_identity = false;
        } else {
            return false;
        }
        return true;
    }
    if app.conn_path.is_some() {
        if esc {
            app.conn_path = None;
        } else if letter('r') {
            app.net.send(duocb_core::net::UiCommand::QueryConnPath);
        } else {
            return false;
        }
        return true;
    }

    if focus_free && app.screen != Screen::Home && esc {
        app.go_back();
        return true;
    }

    let handled = match app.screen {
        Screen::Home if focus_free => handle_configure_key(app, esc, enter, up, down, &letter, &command),
        Screen::CardSetup if focus_free => {
            // S shows a PIN here; C joins with the PIN and optional host IP
            // entered on this screen.
            if letter('s') {
                app.host_card_setup();
                true
            } else if letter('c') {
                app.join_card_setup();
                true
            } else {
                // Anything else falls through to the session shortcuts below.
                false
            }
        }
        Screen::CardPairing => {
            // Copy the current rotating PIN, or mint a new one, without the
            // mouse. `t` is offered plain as well as command-modified: this
            // screen has no text fields, so nothing can be hijacked.
            let has_pin = app.pin_display.is_some();
            if has_pin && (command('t') || (focus_free && letter('t'))) {
                let pin = app.pin_display.clone().unwrap();
                app.copy_with_flash(&pin, CopyTarget::Pin);
                true
            } else if has_pin && focus_free && letter('r') {
                app.net.send(duocb_core::net::UiCommand::RefreshPin);
                true
            } else {
                false
            }
        }
        // Accept or refuse the card only from the screen that shows the
        // fingerprints — trust is never one keystroke away from anywhere else.
        Screen::CardConfirm if focus_free => {
            if enter || letter('i') {
                app.import_received_card();
            } else if letter('c') {
                app.cancel_received_card();
            } else {
                return false;
            }
            true
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
    match app.configure_step {
        ConfigureStep::SetupChoice => {
            if letter('g') {
                app.begin_generate_identity();
            } else if letter('i') {
                app.configure_step = ConfigureStep::SetupImport;
            } else {
                return false;
            }
            true
        }
        ConfigureStep::SetupImport => {
            if letter('u') {
                app.use_imported_identity();
            } else if esc {
                app.cancel_setup();
            } else {
                return false;
            }
            true
        }
        ConfigureStep::SetupName => {
            if enter {
                app.save_name();
            } else if esc && app.has_saved_identity() {
                app.cancel_name();
            } else {
                return false;
            }
            true
        }
        ConfigureStep::Ready => {
            // Every hub action is reachable from the keyboard; the labels carry
            // the letter so a tester never has to look them up.
            if letter('q') {
                app.open_card_setup();
            } else if letter('s') {
                app.begin_server();
            } else if letter('c') {
                app.enter_join_picker();
            } else if letter('r') {
                app.reset_name_field();
                app.configure_step = ConfigureStep::SetupName;
            } else if letter('b') {
                let private_key = app.identity.to_nsec();
                app.copy_with_flash(&private_key, CopyTarget::PrivateKey);
            } else if letter('x') {
                app.confirm_reset_identity = true;
            } else if letter('i') {
                app.import_peer_card();
            } else if command('t') || letter('t') {
                let Some(encoded) = app.self_card.as_ref().map(duocb_core::auth::IdentityCard::encode)
                else {
                    return false;
                };
                app.copy_with_flash(&encoded, CopyTarget::Card);
            } else {
                return false;
            }
            true
        }
        ConfigureStep::Join => {
            if letter('c') || enter {
                app.join_selected_peer();
            } else if down {
                app.move_peer_selection(1);
            } else if up {
                app.move_peer_selection(-1);
            } else if esc {
                app.leave_join_picker();
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
            app.copy_with_flash(&text, CopyTarget::Inbox(0));
        }
    } else if command('o') {
        if let Some(text) = app.outbox.as_ref().map(|i| i.text.clone()) {
            app.copy_with_flash(&text, CopyTarget::Outbox);
        }
    } else if command('d') {
        app.net.send(duocb_core::net::UiCommand::QueryConnPath);
    } else if command('l') {
        app.inbox.clear();
    } else {
        return false;
    }
    true
}

/// Shortcut routing. Every CTA in the app is reachable from the keyboard, which
/// is what lets a QA pass drive the whole flow without the mouse — so these
/// assert the routes exist and, just as importantly, that plain letters stay
/// inert while a text field has focus.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::card_setup_tests::{cleanup, configured_app, peer_card};
    use duocb_core::auth::IdentityCard;

    /// Press a plain (unmodified) key.
    fn plain(app: &mut App, text: &str) -> bool {
        handle_global_key(app, text, true, false, false)
    }

    /// Press a plain key while a text field has focus.
    fn typing(app: &mut App, text: &str) -> bool {
        handle_global_key(app, text, true, false, true)
    }

    #[test]
    fn hub_letters_reach_every_hub_action() {
        let (mut app, path) = configured_app();
        assert_eq!(app.configure_step, ConfigureStep::Ready);

        assert!(plain(&mut app, "q"));
        assert_eq!(app.screen, Screen::CardSetup);
        app.go_back();

        assert!(plain(&mut app, "c"));
        assert_eq!(app.configure_step, ConfigureStep::Join);
        app.leave_join_picker();

        assert!(plain(&mut app, "r"), "R renames");
        assert_eq!(app.configure_step, ConfigureStep::SetupName);
        app.cancel_name();

        assert!(plain(&mut app, "x"), "X asks to reset the identity");
        assert!(app.confirm_reset_identity);
        // Esc dismisses the modal rather than navigating behind it.
        assert!(plain(&mut app, "\u{1b}"));
        assert!(!app.confirm_reset_identity);

        assert!(plain(&mut app, "s"));
        assert_eq!(app.screen, Screen::Server);

        cleanup(app, path);
    }

    /// The card-setup flow end to end on the keyboard alone.
    #[test]
    fn card_setup_flow_is_fully_keyboard_driven() {
        let (mut app, path) = configured_app();

        assert!(plain(&mut app, "q"));
        assert_eq!(app.screen, Screen::CardSetup);

        assert!(plain(&mut app, "s"), "S shows a PIN");
        assert_eq!(app.screen, Screen::CardPairing);

        // Esc backs out of pairing to the card-setup screen.
        assert!(plain(&mut app, "\u{1b}"));
        assert_eq!(app.screen, Screen::CardSetup);

        // A received card, then I imports it.
        app.apply_event(duocb_core::net::NetEvent::PeerCardReceived(Box::new(
            peer_card("laptop", 0),
        )));
        assert_eq!(app.screen, Screen::CardConfirm);
        assert!(plain(&mut app, "i"), "I imports");
        assert_eq!(app.peers.len(), 1);
        assert_eq!(app.screen, Screen::Home);

        cleanup(app, path);
    }

    /// C on the confirmation screen refuses the card, the same as Cancel.
    #[test]
    fn c_refuses_a_pending_card() {
        let (mut app, path) = configured_app();
        app.apply_event(duocb_core::net::NetEvent::PeerCardReceived(Box::new(
            peer_card("laptop", 0),
        )));

        assert!(plain(&mut app, "c"));
        assert!(app.peers.is_empty(), "C must not trust the card");
        assert!(app.pending_peer_card.is_none());
        assert_eq!(app.screen, Screen::CardSetup);

        cleanup(app, path);
    }

    /// Trust is never one stray keystroke away from a screen that is not
    /// showing the fingerprints.
    #[test]
    fn import_only_fires_from_the_confirmation_screen() {
        let (mut app, path) = configured_app();
        app.apply_event(duocb_core::net::NetEvent::PeerCardReceived(Box::new(
            peer_card("laptop", 0),
        )));
        // Navigate away without deciding (the card is dropped by go_back, so
        // re-supply it and force the screen instead).
        app.screen = Screen::Home;
        let pending = peer_card("laptop", 0);
        app.pending_peer_card = Some(pending.clone());

        // On the hub, I is the paste-a-card action, so it consumes the key —
        // but it must act on the (empty) paste field, never on the card waiting
        // behind the confirmation screen.
        plain(&mut app, "i");
        assert!(
            app.peers.is_empty(),
            "I on the hub must not import a pending card"
        );
        assert_eq!(
            app.pending_peer_card.as_ref().map(IdentityCard::public_key),
            Some(pending.public_key()),
            "the pending card must still be waiting on its fingerprint check"
        );

        cleanup(app, path);
    }

    /// A focused text field swallows plain letters, so typing a device name
    /// never triggers a shortcut.
    #[test]
    fn plain_letters_are_inert_while_typing() {
        let (mut app, path) = configured_app();
        for key in ["q", "s", "c", "r", "x", "b", "t", "i"] {
            assert!(!typing(&mut app, key), "{key} must not fire while typing");
        }
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.configure_step, ConfigureStep::Ready);
        assert!(!app.confirm_reset_identity);

        cleanup(app, path);
    }
}
