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

fn main() -> eframe::Result {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("duocb=info"))
        .init();

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
        Box::new(|cc| Ok(Box::new(ui::app::DuocbApp::new(cc)))),
    )
}
