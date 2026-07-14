//! Wires every `Actions` callback from the UI to the [`App`] state: each
//! handler mutates the state and then runs the single [`App::sync`]
//! projection. Navigation-style actions also pull keyboard focus back to the
//! window's shortcut scope so plain-letter shortcuts work right after them.

use std::cell::RefCell;
use std::rc::Rc;

use slint::ComponentHandle;

use super::{App, CopyTarget};
use crate::{Actions, MainWindow, UiState};

pub(crate) fn wire(app: &Rc<RefCell<App>>, ui: &MainWindow) {
    let actions = ui.global::<Actions>();

    /// A plain action: mutate, then sync.
    macro_rules! act {
        ($setter:ident, |$app:ident| $body:expr) => {
            actions.$setter({
                let app = Rc::clone(app);
                let weak = ui.as_weak();
                move || {
                    let ui = weak.unwrap();
                    {
                        #[allow(unused_mut)]
                        let mut $app = app.borrow_mut();
                        $body;
                    }
                    app.borrow().sync(&ui);
                }
            });
        };
    }

    /// A navigation action: mutate, sync, and reclaim keyboard focus for the
    /// shortcut scope (the previous screen's field focus must not linger).
    macro_rules! nav {
        ($setter:ident, |$app:ident| $body:expr) => {
            actions.$setter({
                let app = Rc::clone(app);
                let weak = ui.as_weak();
                move || {
                    let ui = weak.unwrap();
                    {
                        #[allow(unused_mut)]
                        let mut $app = app.borrow_mut();
                        $body;
                    }
                    app.borrow().sync(&ui);
                    ui.invoke_reset_focus();
                }
            });
        };
    }

    // Navigation.
    nav!(on_go_back, |app| app.go_back());
    nav!(on_open_quick, |app| app.open_quick());
    act!(on_dismiss_error, |app| app.error = None);

    // Configure wizard.
    nav!(on_begin_generate, |app| app.begin_generate_secret());
    nav!(on_open_import, |app| {
        app.configure_step = crate::ConfigureStep::SetupImport;
    });
    nav!(on_cancel_setup, |app| app.cancel_setup());
    nav!(on_use_imported, |app| app.use_imported_secret());
    nav!(on_save_name, |app| app.save_name());
    nav!(on_cancel_name, |app| app.cancel_name());
    nav!(on_rename, |app| {
        app.reset_name_field();
        app.configure_step = crate::ConfigureStep::SetupName;
    });
    act!(on_copy_secret, |app| {
        if let Some(secret) = app.secret.clone() {
            app.copy_with_flash(&secret, CopyTarget::Secret);
        }
    });
    act!(on_request_clear_secret, |app| {
        app.confirm_clear_secret = true;
    });
    nav!(on_confirm_clear_secret, |app| {
        app.clear_secret();
        app.confirm_clear_secret = false;
    });
    act!(on_cancel_clear_secret, |app| {
        app.confirm_clear_secret = false;
    });

    // Hub / device picker.
    nav!(on_begin_server, |app| app.begin_server());
    nav!(on_enter_join_picker, |app| app.enter_join_picker());
    nav!(on_leave_join_picker, |app| app.leave_join_picker());
    act!(on_refresh_peers, |app| app.refresh_peers());
    nav!(on_join_selected, |app| app.join_selected_peer());
    actions.on_toggle_peer({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move |suffix| {
            let ui = weak.unwrap();
            app.borrow_mut().toggle_peer(&suffix);
            app.borrow().sync(&ui);
        }
    });

    // Quick options / client.
    actions.on_set_pin_channel({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move |channel| {
            let ui = weak.unwrap();
            app.borrow_mut().set_pin_channel(channel);
            app.borrow().sync(&ui);
        }
    });
    act!(on_select_manual, |app| app.mode = crate::PairMode::Manual);
    act!(on_toggle_quick_advanced, |app| {
        app.quick_advanced_expanded = !app.quick_advanced_expanded
    });
    nav!(on_join_quick, |app| app.join_quick());
    nav!(on_connect_client, |app| app.connect_client());
    nav!(on_disconnect, |app| {
        app.net.send(duocb_core::net::UiCommand::Disconnect);
    });

    // Server credentials.
    act!(on_copy_pairing_code, |app| {
        if let Some(code) = app.pairing_code.clone() {
            app.copy_with_flash(&code, CopyTarget::PairingCode);
        }
    });
    act!(on_copy_pin, |app| {
        if let Some(pin) = app.pin_display.clone() {
            app.copy_with_flash(&pin, CopyTarget::Pin);
        }
    });
    act!(on_refresh_pin, |app| {
        app.net.send(duocb_core::net::UiCommand::RefreshPin);
    });

    // Session panel.
    act!(on_send_clipboard, |app| app.send_clipboard());
    act!(on_compose_send, |app| app.compose_send());
    act!(on_clear_inbox, |app| app.inbox.clear());
    act!(on_query_conn_path, |app| app.query_conn_path());
    act!(on_close_conn_path, |app| app.conn_path = None);
    act!(on_outbox_copy, |app| {
        if let Some(text) = app.outbox.as_ref().map(|i| i.text.clone()) {
            app.copy_with_flash(&text, CopyTarget::Outbox);
        }
    });
    act!(on_outbox_peek, |app| {
        if let Some(item) = app.outbox.as_mut() {
            item.toggle_peek();
        }
    });
    actions.on_inbox_copy({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move |index| {
            let ui = weak.unwrap();
            {
                let mut app = app.borrow_mut();
                if let Some(text) = app.inbox.get(index as usize).map(|i| i.text.clone()) {
                    app.copy_with_flash(&text, CopyTarget::Inbox(index as usize));
                }
            }
            app.borrow().sync(&ui);
        }
    });
    actions.on_inbox_peek({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move |index| {
            let ui = weak.unwrap();
            {
                let mut app = app.borrow_mut();
                if let Some(item) = app.inbox.get_mut(index as usize) {
                    item.toggle_peek();
                }
            }
            app.borrow().sync(&ui);
        }
    });

    // Input mirroring: keep the Rust mirrors current on every keystroke so
    // validation-derived properties recompute live.
    actions.on_fields_edited({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            {
                let s = ui.global::<UiState>();
                let mut app = app.borrow_mut();
                app.in_my_name = s.get_in_my_name().into();
                app.in_import_token = s.get_in_import_token().into();
                // Sanitize each PIN group (uppercase, map look-alikes, drop
                // noise) then cap/spill them into the two fields. No separator is
                // ever inserted into a field, so the cursor never shifts under
                // the typist; a paste of the whole code into the first group
                // spills its overflow into the empty second group.
                let (a, b) = duocb_core::pin::split_pin_groups(
                    &duocb_core::pin::sanitize_pin_chars(&s.get_in_pin_a()),
                    &duocb_core::pin::sanitize_pin_chars(&s.get_in_pin_b()),
                );
                app.in_pin_a = a;
                app.in_pin_b = b;
                app.in_manual_code = s.get_in_manual_code().into();
                app.in_compose = s.get_in_compose().into();
            }
            app.borrow().sync(&ui);
        }
    });

    // Global shortcuts from the root focus scope.
    actions.on_global_key({
        let app = Rc::clone(app);
        let weak = ui.as_weak();
        move |text, plain, command, field_focused| {
            let ui = weak.unwrap();
            let handled = super::keys::handle_global_key(
                &mut app.borrow_mut(),
                &text,
                plain,
                command,
                field_focused,
            );
            app.borrow().sync(&ui);
            handled
        }
    });
}
