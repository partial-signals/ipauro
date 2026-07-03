//! The `eframe::App` impl. Owns exactly the state the M0 ticket allows: the
//! last-received connection/snapshot state and which of the two view modes
//! is showing — nothing the service doesn't already have.
//!
//! Split across `eframe` 0.35's `App::logic`/`App::ui`: `logic` drains the
//! IPC and tray-menu channels and applies viewport commands, and runs
//! regardless of window visibility, so tray clicks and IPC updates are
//! handled even while the window is hidden or in widget mode; `ui` only
//! draws, and only when the window is actually visible.

use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use eframe::egui::{self, ViewportCommand, WindowLevel};
use ipauro_proto::ipc::Command;

use crate::state::{reduce, reduce_status, ConnEvent, ConnState, StatusLine};
use crate::tray::{self, TrayAction};
use crate::{ipc_client, panel, theme, widget};

/// Fixed panel size — "~360×440" per the M0 ticket.
pub const PANEL_SIZE: egui::Vec2 = egui::vec2(360.0, 440.0);
/// Fixed compact-widget size — "~200×64" per the M0 ticket.
pub const WIDGET_SIZE: egui::Vec2 = egui::vec2(200.0, 64.0);

/// How often `logic` re-runs while otherwise idle, so tray-menu clicks and
/// IPC events are noticed promptly even with the window hidden (where
/// nothing else would wake the event loop). IPC events also call
/// `request_repaint()` directly and so arrive sooner than this in practice;
/// this is the backstop for tray/menu events, which have no such hook.
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Panel,
    Widget,
}

/// The single root viewport's desired shape. Compared against what was last
/// applied so we only issue `ViewportCommand`s on an actual change, instead
/// of fighting a user's manual window drag every frame.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Desired {
    mode: ViewMode,
    visible: bool,
}

pub struct IpauroApp {
    conn: ConnState,
    /// Transient, UI-only status line (command errors, "starting
    /// service…") — folded from the same `ConnEvent` stream as `conn`, but
    /// kept separate since it's not part of what the service reports in a
    /// `Snapshot`. See `state::StatusLine`'s doc comment.
    status: StatusLine,
    ipc_events: Receiver<ConnEvent>,
    commands: Sender<Command>,
    mode: ViewMode,
    visible: bool,
    applied: Option<Desired>,
    quitting: bool,
    /// Kept alive only to keep the tray icon alive: dropping a `TrayIcon`
    /// removes it from the menu bar.
    _tray: tray_icon::TrayIcon,
}

impl IpauroApp {
    pub fn new(cc: &eframe::CreationContext<'_>, tray: tray_icon::TrayIcon) -> Self {
        theme::apply(&cc.egui_ctx);
        let (ipc_events, commands) = ipc_client::spawn(cc.egui_ctx.clone());
        Self {
            conn: ConnState::default(),
            status: StatusLine::default(),
            ipc_events,
            commands,
            mode: ViewMode::Panel,
            visible: false,
            applied: None,
            quitting: false,
            _tray: tray,
        }
    }

    fn drain_ipc_events(&mut self) {
        while let Ok(event) = self.ipc_events.try_recv() {
            self.status = reduce_status(&self.status, &event);
            self.conn = reduce(&self.conn, event);
        }
    }

    fn drain_tray_menu(&mut self) {
        while let Ok(menu_event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            match tray::action_for_id(menu_event.id()) {
                Some(TrayAction::OpenPanel) => {
                    self.mode = ViewMode::Panel;
                    self.visible = true;
                }
                Some(TrayAction::CompactWidget) => {
                    self.mode = ViewMode::Widget;
                    self.visible = true;
                }
                Some(TrayAction::InstallHelper) => {
                    let _ = self.commands.send(Command::RegisterHelper);
                }
                Some(TrayAction::Quit) => self.quitting = true,
                // An id we didn't create — nothing to do (see
                // `tray::action_for_id`'s doc comment).
                None => {}
            }
        }
    }

    /// Hide instead of quitting when the user clicks the window's own close
    /// button — quitting is tray-menu-only, handled separately in `logic`.
    fn intercept_close(&mut self, ctx: &egui::Context) {
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && !self.quitting {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.visible = false;
        }
    }

    fn apply_viewport(&mut self, ctx: &egui::Context) {
        let desired = Desired { mode: self.mode, visible: self.visible };
        if self.applied == Some(desired) {
            return;
        }
        let (size, level, decorations) = match desired.mode {
            ViewMode::Panel => (PANEL_SIZE, WindowLevel::Normal, true),
            ViewMode::Widget => (WIDGET_SIZE, WindowLevel::AlwaysOnTop, false),
        };
        ctx.send_viewport_cmd(ViewportCommand::Resizable(false));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize(size));
        ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(size));
        ctx.send_viewport_cmd(ViewportCommand::MaxInnerSize(size));
        ctx.send_viewport_cmd(ViewportCommand::Decorations(decorations));
        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(level));
        ctx.send_viewport_cmd(ViewportCommand::Visible(desired.visible));
        self.applied = Some(desired);
    }
}

impl eframe::App for IpauroApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_ipc_events();
        self.drain_tray_menu();
        self.intercept_close(ctx);

        if self.quitting {
            // Proactively request a close rather than waiting for another
            // close_requested cycle — the window may already be hidden, in
            // which case no OS close event will ever arrive on its own.
            ctx.send_viewport_cmd(ViewportCommand::Close);
        } else {
            self.apply_viewport(ctx);
        }

        ctx.request_repaint_after(IDLE_POLL_INTERVAL);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        match self.mode {
            ViewMode::Panel => panel::show(ui, &self.conn, &self.status, &self.commands),
            ViewMode::Widget => widget::show(ui, &self.conn),
        }
    }
}
