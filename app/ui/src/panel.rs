//! The Control-Center-style panel: status rows for the service, helper, and
//! bridge, plus one prominent bridge toggle. Purely a function of
//! [`ConnState`] — no local widget state, so it renders correctly on the
//! very first frame after opening mid-session (the M0 ticket's binding
//! "renders instantly from snapshot" requirement). Layout only for now;
//! stock `egui::Style` — see `theme.rs`.

use std::sync::mpsc::Sender;
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Color32, Ui};
use ipauro_proto::ipc::Command;

use crate::state::{ConnState, RebindWatch, StatusLine};
use crate::viewmodel::{panel_view_model, rebind_view_model, status_line_view_model};

/// Color for an error-flagged status line — a muted red, distinguishable
/// from ordinary text without shouting.
const ERROR_COLOR: Color32 = Color32::from_rgb(214, 69, 69);
/// Color for the rebind callout — amber, not red: nothing is broken in the
/// service, there is one thing for the operator to do.
const WARN_COLOR: Color32 = Color32::from_rgb(255, 159, 10);

/// What the panel needs the app to do that isn't a service [`Command`].
/// Returned rather than applied in place so `panel.rs` keeps taking shared
/// references and stays a pure function of the state it's handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PanelOutcome {
    /// The operator dismissed the rebind callout this frame.
    pub rebind_dismissed: bool,
}

pub fn show(
    ui: &mut Ui,
    conn: &ConnState,
    status: &StatusLine,
    rebind: &RebindWatch,
    commands: &Sender<Command>,
) -> PanelOutcome {
    let mut outcome = PanelOutcome::default();
    egui::CentralPanel::default().show(ui, |ui| {
        match conn.snapshot() {
            None => show_not_running(ui),
            Some(snapshot) => {
                let now_unix = now_unix();
                let vm = panel_view_model(snapshot, now_unix);
                ui.heading("IPAuRo");
                ui.separator();
                outcome.rebind_dismissed = show_rebind_callout(ui, rebind);
                show_status(ui, &vm, commands);
            }
        }
        show_status_line(ui, status);
    });
    outcome
}

/// The latched "the bridge was rebuilt under you" callout, above everything
/// else because it's the one thing on this panel that needs the operator to
/// act. Returns whether they dismissed it.
///
/// Deliberately not shown on the "service not running" screen: the recovery
/// is "rejoin the new bridge", and with no service there is no bridge to
/// rejoin yet — that screen's own message is the more actionable one. The
/// latch survives regardless (see [`RebindWatch`]), so the callout is back as
/// soon as a snapshot is.
fn show_rebind_callout(ui: &mut Ui, rebind: &RebindWatch) -> bool {
    let Some(vm) = rebind_view_model(rebind) else { return false };
    let mut dismissed = false;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.label(egui::RichText::new(vm.text).color(WARN_COLOR).strong());
        ui.label(egui::RichText::new(vm.action).color(WARN_COLOR));
        if ui.button(vm.dismiss_label).clicked() {
            dismissed = true;
        }
    });
    ui.add_space(8.0);
    dismissed
}

fn show_not_running(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 2.0 - 24.0);
        ui.heading("IPAuRo");
        ui.label("Service not running");
    });
}

/// The status rows themselves. The panel's heading, separator and rebind
/// callout are rendered by [`show`] above this — they're panel chrome, not
/// snapshot rows.
fn show_status(ui: &mut Ui, vm: &crate::viewmodel::PanelViewModel, commands: &Sender<Command>) {
    ui.label(egui::RichText::new("Service").strong());
    ui.label(&vm.service_line);
    ui.add_space(8.0);

    ui.label(egui::RichText::new("Helper").strong());
    ui.label(&vm.helper_line);
    if let Some(hint) = &vm.helper_hint {
        ui.label(egui::RichText::new(hint).italics());
    }
    if let Some(label) = &vm.helper_button_label {
        let button = egui::Button::new(egui::RichText::new(label).size(14.0));
        if ui.add_sized([ui.available_width(), 28.0], button).clicked() {
            let _ = commands.send(Command::RegisterHelper);
        }
    }
    ui.add_space(8.0);

    ui.label(egui::RichText::new("Bridge").strong());
    ui.label(&vm.bridge_name_line);
    ui.label(format!("Members: {}", vm.bridge_members_line));
    ui.label(format!("IPv4: {}", vm.bridge_ipv4_line));
    ui.add_space(12.0);

    let label = if vm.bridge_desired_up { "Turn Bridge Off" } else { "Turn Bridge On" };
    let button = egui::Button::new(egui::RichText::new(label).size(16.0));
    if ui.add_sized([ui.available_width(), 36.0], button).clicked() {
        let command = if vm.bridge_desired_up { Command::BridgeDown } else { Command::BridgeUp };
        let _ = commands.send(command);
    }
    ui.add_space(8.0);

    ui.label(egui::RichText::new("Transport").strong());
    ui.label(format!("Link scope: {}", vm.link_scope_line));
    ui.label(format!("DHCP: {}", vm.dhcp_line));
    ui.add_space(12.0);

    let scope_label =
        if vm.link_scope_desired { "Turn Link Scope Off" } else { "Turn Link Scope On" };
    let scope_button = egui::Button::new(egui::RichText::new(scope_label).size(16.0));
    if ui.add_sized([ui.available_width(), 36.0], scope_button).clicked() {
        let _ = commands.send(Command::SetTransportScope { enabled: !vm.link_scope_desired });
    }
}

/// The transient command-status/"starting service…" line. Renders nothing
/// when `status_line_view_model` returns `None` — no snapshot rendering, no
/// enum-variant matching here, just the pre-formatted view model.
fn show_status_line(ui: &mut Ui, status: &StatusLine) {
    let Some(vm) = status_line_view_model(status) else { return };
    ui.add_space(8.0);
    ui.separator();
    let color = if vm.is_error { ERROR_COLOR } else { ui.visuals().weak_text_color() };
    ui.label(egui::RichText::new(vm.text).color(color));
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
