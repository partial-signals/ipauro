//! `ipauro-probe grants` — print what macOS has recorded about each app's
//! Local Network (multicast) access.
//!
//! Complements `check`: `check` says whether traffic flowed *now*, `grants`
//! says what decision the system is carrying, which is what makes a matrix row
//! reproducible. A context that comes back open may simply have been approved
//! long ago, and a denial persists with no prompt ever shown again — neither
//! is visible from behaviour alone.

use std::process::ExitCode;

use anyhow::Result;

use crate::cli::GrantsArgs;
use crate::grants;

/// Exit code when `--denied-only` is asked for and at least one denial exists,
/// so a script can gate on "is anything denied here" without parsing output.
const EXIT_FOUND_DENIALS: u8 = 4;

pub fn run(args: GrantsArgs) -> Result<ExitCode> {
    let all = grants::load()?;
    let shown: Vec<_> = all
        .iter()
        .filter(|g| args.filter.as_deref().is_none_or(|needle| g.matches(needle)))
        .filter(|g| !args.denied_only || (g.decided && g.denied))
        .collect();

    println!("registry: {}", grants::REGISTRY_PATH);
    println!("{:<10} {:<46} PATH", "DECISION", "IDENTIFIER");
    println!("{}", "-".repeat(100));
    for grant in &shown {
        println!(
            "{:<10} {:<46} {}",
            grant.decision(),
            grant.identifier.as_deref().unwrap_or("<none>"),
            grant.path.as_deref().unwrap_or("")
        );
    }

    let tally = grants::tally(&all);
    let denied = tally.get("DENIED").copied().unwrap_or(0);
    println!();
    println!(
        "{} of {} record(s) shown — {} denied, {} allowed, {} unset (no explicit decision; \
         behaves as allowed)",
        shown.len(),
        all.len(),
        denied,
        tally.get("allowed").copied().unwrap_or(0),
        tally.get("unset").copied().unwrap_or(0),
    );

    if args.denied_only && denied > 0 {
        return Ok(ExitCode::from(EXIT_FOUND_DENIALS));
    }
    Ok(ExitCode::SUCCESS)
}
