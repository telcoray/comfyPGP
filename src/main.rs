// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod decrypt;
mod encrypt;
mod fallback;
mod keygen;
mod policy;
mod sign;
mod store;

fn main() -> eframe::Result {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("comfyPGP")
        .with_inner_size([640.0, 860.0])
        .with_min_inner_size([480.0, 420.0]);
    // Window and taskbar icon (the .exe icon is embedded by build.rs).
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "comfyPGP",
        options,
        Box::new(|_cc| Ok(Box::new(app::ComfyApp::new()))),
    )
}
