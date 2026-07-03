//! ipauro-ui — egui tray client over the IPC API (ticket R002-T1).
//!
//! Entry point only: builds the initial (hidden) window + the programmatic
//! icon, then hands off to `eframe::run_native`. The tray icon itself is
//! built from within [`app::IpauroApp::new`] — see `tray::build`'s doc
//! comment for why that has to happen there and not here. The window starts
//! hidden; the tray menu ("Open Panel" / "Compact Widget") is the only way
//! to show it, and "Quit" is the only way to exit — closing the window via
//! its own close button just hides it (`app::IpauroApp::logic`).

mod app;
mod icon;
mod ipc_client;
mod panel;
mod service_bootstrap;
mod state;
mod theme;
mod tray;
mod viewmodel;
mod widget;

const ICON_SIZE: u32 = 64;

fn main() -> eframe::Result {
    env_logger::init();

    let icon_data = eframe::egui::IconData {
        rgba: icon::circle_rgba(ICON_SIZE, icon::ACCENT),
        width: ICON_SIZE,
        height: ICON_SIZE,
    };

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("IPAuRo")
            .with_inner_size(app::PANEL_SIZE)
            .with_resizable(false)
            .with_visible(false)
            .with_icon(icon_data),
        ..Default::default()
    };

    eframe::run_native(
        "IPAuRo",
        native_options,
        Box::new(|cc| {
            let tray = tray::build()?;
            Ok(Box::new(app::IpauroApp::new(cc, tray)))
        }),
    )
}
