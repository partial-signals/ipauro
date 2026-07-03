//! The compact always-on-top widget: a bridge status dot + member count.
//! An explicit placeholder for the future metering strip (W001 §4's "UI
//! client" bullet) — no per-channel meters yet, just enough to prove the
//! toggle-from-tray plumbing and render the one number that matters at a
//! glance.

use eframe::egui::{self, Color32, Ui};

use crate::state::ConnState;
use crate::viewmodel::compact_view_model;

const UP_COLOR: Color32 = Color32::from_rgb(52, 199, 89);
const DOWN_COLOR: Color32 = Color32::GRAY;

pub fn show(ui: &mut Ui, conn: &ConnState) {
    egui::CentralPanel::default().show(ui, |ui| {
        ui.horizontal_centered(|ui| match conn.snapshot() {
            None => {
                dot(ui, DOWN_COLOR);
                ui.label("Not running");
            }
            Some(snapshot) => {
                let vm = compact_view_model(snapshot);
                dot(ui, if vm.bridge_up { UP_COLOR } else { DOWN_COLOR });
                let suffix = if vm.member_count == 1 { "" } else { "s" };
                ui.label(format!("{} member{suffix}", vm.member_count));
            }
        });
    });
}

fn dot(ui: &mut Ui, color: Color32) {
    let size = egui::vec2(14.0, 14.0);
    let (rect, _response) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), size.x / 2.0, color);
}
