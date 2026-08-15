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

/// Everything the command line decides. Both settings are launch-time only:
/// neither is persisted, so a config carries no memory of how it was started.
struct Cli {
    /// Explicit config path (`--config`/`-c`, else `DUOCB_CONFIG`).
    config: Option<PathBuf>,
    /// Which transport(s) carry signaling — both the card-setup PIN rendezvous
    /// and the hosting records a clipboard session is found through.
    signal_channel: duocb_core::net::SignalChannel,
}

/// Parse this process's arguments, falling back to `DUOCB_CONFIG` for the
/// config path.
fn parse_cli() -> Result<Cli, Box<dyn std::error::Error>> {
    let mut cli = parse_args(std::env::args_os().skip(1))?;
    cli.config = cli
        .config
        .or_else(|| std::env::var_os("DUOCB_CONFIG").map(PathBuf::from));
    Ok(cli)
}

/// Parse the arguments this binary understands. Unrecognized arguments are
/// ignored (the windowing toolkit gets its own), but a malformed value for a
/// flag we *do* own is an error rather than a silently different setup — a
/// channel override that was quietly dropped would make a test look like it
/// exercised a path it never touched.
fn parse_args(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Cli, Box<dyn std::error::Error>> {
    use duocb_core::net::SignalChannel;

    let mut config = None;
    let (mut lan_only, mut nostr_only) = (false, false);
    let mut args = args;
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            let path = args.next().ok_or("--config requires a path")?;
            // An empty value is rejected in both forms: `config::resolve_path`
            // would otherwise take "" as an explicit override and fail deeper
            // in, or silently target the process's own directory.
            if path.is_empty() {
                return Err("--config requires a path".into());
            }
            config = Some(PathBuf::from(path));
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--config=")) {
            if value.is_empty() {
                return Err("--config requires a path".into());
            }
            config = Some(PathBuf::from(value));
        } else if arg == "--lan-only" {
            lan_only = true;
        } else if arg == "--nostr-only" {
            nostr_only = true;
        }
    }
    let signal_channel = match (lan_only, nostr_only) {
        (true, true) => {
            return Err("--lan-only and --nostr-only cannot both be given".into());
        }
        (true, false) => SignalChannel::LanOnly,
        (false, true) => SignalChannel::NostrOnly,
        (false, false) => SignalChannel::LanThenNostr,
    };
    Ok(Cli {
        config,
        signal_channel,
    })
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
        // font and resolves reliably through the platform font database.
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
    state.set_app_version(env!("CARGO_PKG_VERSION").into());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("duocb=info,duocb_core=info"),
    )
    .init();

    let cli = parse_cli()?;
    let config_path = config::resolve_path(cli.config)?;
    // The lock is held (and moved into the app) until the GUI exits. A second
    // process may run only with another explicit config path, which gives
    // same-machine E2E tests isolated state.
    let config_lock = config::acquire_lock(&config_path)?;
    // Load before initializing the UI or networking so invalid persisted state
    // terminates startup without starting any application services.
    let config = config_lock.load()?;

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

    let app = Rc::new(RefCell::new(app::App::new(
        config_lock,
        config,
        net,
        cli.signal_channel,
    )));
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use duocb_core::net::SignalChannel;

    fn parse(args: &[&str]) -> Result<Cli, String> {
        parse_args(args.iter().map(std::ffi::OsString::from)).map_err(|e| e.to_string())
    }

    /// Signaling defaults to LAN-first-with-nostr-fallback, and each override
    /// pins it to exactly one transport — that is the whole point of the flags,
    /// so a test that forces one path really gets only that path.
    #[test]
    fn signal_channel_flags_pin_a_single_transport() {
        assert_eq!(
            parse(&[]).unwrap().signal_channel,
            SignalChannel::LanThenNostr
        );
        assert_eq!(
            parse(&["--lan-only"]).unwrap().signal_channel,
            SignalChannel::LanOnly
        );
        assert_eq!(
            parse(&["--nostr-only"]).unwrap().signal_channel,
            SignalChannel::NostrOnly
        );
        // Asking for both is a contradiction, not a silent winner.
        assert!(parse(&["--lan-only", "--nostr-only"]).is_err());
    }

    /// The channel flags sit alongside `--config`, which same-machine E2E runs
    /// always pass, and neither form of it swallows them.
    #[test]
    fn config_and_channel_flags_coexist() {
        let cli = parse(&["--config", "/tmp/peer1.json", "--nostr-only"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/peer1.json")));
        assert_eq!(cli.signal_channel, SignalChannel::NostrOnly);

        let cli = parse(&["--lan-only", "--config=/tmp/peer2.json"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/peer2.json")));
        assert_eq!(cli.signal_channel, SignalChannel::LanOnly);

        let cli = parse(&["-c", "/tmp/peer3.json"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/peer3.json")));

        assert!(parse(&["--config"]).is_err(), "a path is required");
        // An empty path is not a path in either form.
        assert!(parse(&["--config="]).is_err());
        assert!(parse(&["--config", ""]).is_err());
        assert!(parse(&["-c", ""]).is_err());
    }
}
