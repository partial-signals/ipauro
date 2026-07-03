//! Theming stub — applies nothing yet.
//!
//! Every visual in this crate right now (stock `egui::Style`/`Visuals`,
//! default fonts, plain labels/dots standing in for meters) is scaffolding,
//! not the shipped look. Per `.yah/docs/working/W001-ipauro-plan.md` §7 and
//! the M0 ticket's second gotcha
//! (`.yah/docs/architecture/A001-ipauro-architecture.md`, `R002-T1`): egui
//! reads as a dev-tool out of the box, and a Control-Center-style surface
//! lives entirely on polish. The team committed to a real theming pass —
//! custom `Style`/`Visuals` (spacing, corner rounding, palette), deliberate
//! fonts, and bespoke meter widgets replacing today's plain rows — as part
//! of this UI client's definition of done, not a nice-to-have. That pass
//! lands here.
//!
//! [`apply`] is the wiring point (`app.rs::IpauroApp::new` already calls it)
//! so turning the pass on is an edit to this file alone, not a hunt through
//! the rest of the crate.

use eframe::egui;

/// Apply the house theme. Currently a no-op — see the module doc comment.
pub fn apply(_ctx: &egui::Context) {
    // Intentionally empty. The theming pass sets `_ctx.set_style(..)` /
    // `_ctx.set_fonts(..)` here.
}
