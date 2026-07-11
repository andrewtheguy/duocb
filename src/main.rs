mod auth;
mod clipboard;
mod config;
mod net;
mod nostr;
mod pin;
mod pin_auth;
mod protocol;
mod ui;

use eframe::egui;
use std::path::PathBuf;

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("duocb=info"))
        .init();

    let config_path = config::resolve_path(config_override()?)?;
    // Held until the GUI exits. A second process may run only with another
    // explicit config path, which gives same-machine E2E tests isolated state.
    let _config_lock = config::acquire_lock(&config_path)?;

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([520.0, 680.0])
        .with_min_inner_size([420.0, 480.0])
        .with_title("duocb");

    // Window/Dock icon, baked from icons/icon.png at build time.
    match eframe::icon_data::from_png_bytes(include_bytes!("../icons/icon.png")) {
        Ok(icon) => viewport = viewport.with_icon(icon),
        Err(err) => log::warn!("failed to load app icon: {err}"),
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "duocb",
        options,
        Box::new(move |cc| {
            Ok(Box::new(ui::app::DuocbApp::new(
                cc,
                config_path.clone(),
            )))
        }),
    )?;
    Ok(())
}
