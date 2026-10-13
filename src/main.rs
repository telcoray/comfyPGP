// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod keygen;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("comfyPGP")
            .with_inner_size([620.0, 680.0])
            .with_min_inner_size([480.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "comfyPGP",
        options,
        Box::new(|_cc| Ok(Box::new(app::ComfyApp::default()))),
    )
}
