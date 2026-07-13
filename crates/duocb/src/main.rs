// On Windows, build a GUI-subsystem executable in release so launching the app
// doesn't spawn an extra console window. Debug builds keep the console so
// `cargo run` still surfaces stderr/logs. No effect on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod clipboard;
mod config;

slint::include_modules!();

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

fn config_override() -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let mut explicit = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            let path = args.next().ok_or("--config requires a path")?;
            explicit = Some(PathBuf::from(path));
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--config=")) {
            if value.is_empty() {
                return Err("--config requires a path".into());
            }
            explicit = Some(PathBuf::from(value));
        }
    }
    Ok(explicit.or_else(|| std::env::var_os("DUOCB_CONFIG").map(PathBuf::from)))
}

/// Pick the platform's native UI and monospace font families. Slint's
/// `font-family` takes a single name (no fallback lists), so the per-OS
/// choice lives here; an empty UI font leaves the renderer's default.
/// `DUOCB_UI_FONT` overrides the UI family (useful on Linux, where the
/// default is whatever fontconfig considers sans).
fn set_platform_fonts(ui: &MainWindow) {
    use slint::ComponentHandle;
    let (ui_font, mono_font) = if cfg!(target_os = "macos") {
        // ".SF NS" is the hidden family name of the San Francisco system
        // font; the friendlier aliases (".AppleSystemUIFont", "SF Pro") do
        // not resolve through Skia's CoreText matching.
        (".SF NS", "Menlo")
    } else if cfg!(target_os = "windows") {
        ("Segoe UI", "Consolas")
    } else {
        ("", "monospace")
    };
    let state = ui.global::<UiState>();
    let ui_font = std::env::var("DUOCB_UI_FONT").unwrap_or_else(|_| ui_font.to_string());
    state.set_ui_font(ui_font.into());
    state.set_mono_font(mono_font.into());
    // The command-modifier label for shortcut hints: ⌘ on macOS, Ctrl elsewhere
    // (matching Slint's `control` modifier), so hints show only the one that
    // applies to this build instead of always "Ctrl/⌘".
    state.set_cmd_label(if cfg!(target_os = "macos") { "⌘" } else { "Ctrl" }.into());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("duocb=info,duocb_core=info"),
    )
    .init();

    let config_path = config::resolve_path(config_override()?)?;
    // The lock is held (and moved into the app) until the GUI exits. A second
    // process may run only with another explicit config path, which gives
    // same-machine E2E tests isolated state.
    let config_lock = config::acquire_lock(&config_path)?;

    let ui = MainWindow::new()?;
    set_platform_fonts(&ui);

    // The runtime's wake signal: Send+Sync and captures no UI state — the
    // event-drain task below owns the (non-Send) app and window instead.
    // Notify holds a permit, so a wake racing a finishing drain re-runs the
    // loop and no event is ever missed.
    let notify = Arc::new(tokio::sync::Notify::new());
    let net = duocb_core::net::spawn_net_runtime(Some(Arc::new({
        let notify = Arc::clone(&notify);
        move || notify.notify_one()
    })));

    let app = Rc::new(RefCell::new(app::App::new(config_lock, net)));
    app::callbacks::wire(&app, &ui);
    app.borrow().sync(&ui);

    // Drain runtime events on the Slint event loop whenever the runtime
    // signals; events queued before the loop starts are drained on the first
    // pass thanks to the stored permit.
    slint::spawn_local({
        let app = Rc::clone(&app);
        let weak = ui.as_weak();
        async move {
            loop {
                notify.notified().await;
                let Some(ui) = weak.upgrade() else { break };
                if app.borrow_mut().drain_events() {
                    app.borrow().sync(&ui);
                }
            }
        }
    })?;

    // One heartbeat covers all periodic UI work: peek expiry, the flash and
    // PIN countdowns, "seen Xm ago" labels, and the device picker's 30 s
    // auto-refresh (all state-derived inside tick + sync).
    let heartbeat = slint::Timer::default();
    heartbeat.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(500),
        {
            let app = Rc::clone(&app);
            let weak = ui.as_weak();
            move || {
                if let Some(ui) = weak.upgrade() {
                    app.borrow_mut().tick();
                    app.borrow().sync(&ui);
                }
            }
        },
    );

    let result = ui.run();
    // Window closed: stop sessions and join the runtime thread before the
    // config lock drops.
    app.borrow_mut().net.shutdown();
    result?;
    Ok(())
}
