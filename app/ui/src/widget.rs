//! The compact always-on-top widget: a bridge status dot + member count +
//! a tiny Link-scope dot. An explicit placeholder for the future metering
//! strip (W001 §4's "UI client" bullet) — no per-channel meters yet, just
//! enough to prove the toggle-from-tray plumbing and render the numbers
//! that matter at a glance.

use eframe::egui::{self, Color32, Ui};

use crate::state::{ConnState, RebindWatch};
use crate::viewmodel::compact_view_model;

const UP_COLOR: Color32 = Color32::from_rgb(52, 199, 89);
const DOWN_COLOR: Color32 = Color32::GRAY;
/// Distinct from `UP_COLOR`/`DOWN_COLOR` so the scope dot doesn't read as
/// "another bridge dot" at a glance.
const SCOPE_COLOR: Color32 = Color32::from_rgb(10, 132, 255);
/// Matches `panel.rs`'s rebind callout, so the two modes read as the same
/// alert.
const REBIND_COLOR: Color32 = Color32::from_rgb(255, 159, 10);

pub fn show(ui: &mut Ui, conn: &ConnState, rebind: &RebindWatch) {
    egui::CentralPanel::default().show(ui, |ui| {
        ui.horizontal_centered(|ui| match conn.snapshot() {
            None => {
                dot(ui, DOWN_COLOR, 14.0);
                ui.label("Not running");
            }
            Some(snapshot) => {
                let vm = compact_view_model(snapshot, rebind);
                dot(ui, if vm.bridge_up { UP_COLOR } else { DOWN_COLOR }, 14.0);
                let suffix = if vm.member_count == 1 { "" } else { "s" };
                ui.label(format!("{} member{suffix}", vm.member_count));
                ui.add_space(6.0);
                dot(ui, if vm.link_scoped { SCOPE_COLOR } else { DOWN_COLOR }, 8.0);
                // The widget is the always-on-top mode an operator leaves
                // open mid-session, so the rebind alert has to reach here —
                // otherwise it's invisible exactly when it matters. Dismissing
                // it stays a panel action: there's no room for a button here,
                // and acknowledging deserves the full explanation.
                if vm.rebind_pending {
                    ui.add_space(6.0);
                    dot(ui, REBIND_COLOR, 8.0);
                    ui.label(egui::RichText::new("rebind").color(REBIND_COLOR))
                        .on_hover_text("Bridge was rebuilt — restart your audio app to rejoin");
                }
            }
        });
    });
}

fn dot(ui: &mut Ui, color: Color32, diameter: f32) {
    let size = egui::vec2(diameter, diameter);
    let (rect, _response) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), size.x / 2.0, color);
}
