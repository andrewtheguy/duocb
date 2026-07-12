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
