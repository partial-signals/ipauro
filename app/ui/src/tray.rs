//! Tray icon + menu construction, and the pure mapping from a clicked menu
//! item's id to the [`TrayAction`] it represents. `IpauroApp::logic` polls
//! `tray_icon::menu::MenuEvent::receiver()` and calls [`action_for_id`] on
//! whatever comes out — the raw string ids never leak past this module.

use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::icon;

const OPEN_PANEL_ID: &str = "open_panel";
const COMPACT_WIDGET_ID: &str = "compact_widget";
const INSTALL_HELPER_ID: &str = "install_helper";
const QUIT_ID: &str = "quit";

/// Actions the tray menu can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    OpenPanel,
    CompactWidget,
    /// Send `Command::RegisterHelper` without requiring the panel to be
    /// open — the same action the panel's "Install Helper…"/"Re-check"
    /// button sends (`registrar.register()` is idempotent, so clicking this
    /// when the helper is already registered/connected is a harmless no-op
    /// status refresh, not an error).
    InstallHelper,
    Quit,
}

/// Map a fired [`tray_icon::menu::MenuEvent`]'s id to the [`TrayAction`] it
/// represents. `None` for any id we didn't create ourselves (defensive —
/// muda ids are otherwise process-unique) rather than a wildcard default
/// action.
pub fn action_for_id(id: &MenuId) -> Option<TrayAction> {
    match id.as_ref() {
        OPEN_PANEL_ID => Some(TrayAction::OpenPanel),
        COMPACT_WIDGET_ID => Some(TrayAction::CompactWidget),
        INSTALL_HELPER_ID => Some(TrayAction::InstallHelper),
        QUIT_ID => Some(TrayAction::Quit),
        _ => None,
    }
}

/// Build the tray icon and its menu ("Open Panel" / "Compact Widget" /
/// "Install Helper" / "Quit").
///
/// **macOS quirk:** tray icons (and their menus) may only be created on the
/// main thread, and only once the OS event loop is actually running — see
/// `tray-icon`'s own platform notes. `eframe`'s `AppCreator` closure (see
/// `main.rs`, wired through to [`crate::app::IpauroApp::new`]) runs from
/// winit's `resumed()` callback, which satisfies that: it's the same
/// integration point the crate's own docs point at (roughly winit's
/// `StartCause::Init`), so building the tray there — rather than before
/// handing control to `eframe::run_native` — is the established, simple
/// pattern rather than a clever workaround.
pub fn build() -> anyhow::Result<TrayIcon> {
    let menu = Menu::with_id_and_items(
        "ipauro-tray-menu",
        &[
            &MenuItem::with_id(OPEN_PANEL_ID, "Open Panel", true, None),
            &MenuItem::with_id(COMPACT_WIDGET_ID, "Compact Widget", true, None),
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id(INSTALL_HELPER_ID, "Install Helper", true, None),
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id(QUIT_ID, "Quit", true, None),
        ],
    )?;

    let rgba = icon::circle_rgba(32, icon::ACCENT);
    let tray_icon = Icon::from_rgba(rgba, 32, 32)?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(tray_icon)
        .with_tooltip("IPAuRo")
        .build()?;
    Ok(tray)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_ids() {
        assert_eq!(action_for_id(&MenuId::new(OPEN_PANEL_ID)), Some(TrayAction::OpenPanel));
        assert_eq!(action_for_id(&MenuId::new(COMPACT_WIDGET_ID)), Some(TrayAction::CompactWidget));
        assert_eq!(
            action_for_id(&MenuId::new(INSTALL_HELPER_ID)),
            Some(TrayAction::InstallHelper)
        );
        assert_eq!(action_for_id(&MenuId::new(QUIT_ID)), Some(TrayAction::Quit));
    }

    #[test]
    fn unknown_id_maps_to_none() {
        assert_eq!(action_for_id(&MenuId::new("something-else")), None);
    }
}
