//! `ipauro-helper --pf-console` — drive the REAL [`PfctlExecutor`] from a
//! line protocol on stdin, with no XPC listener and no other executor.
//!
//! Exists for the macOS-VM L2 tier (`crates/ipauro-vmlab`, R009-T2): pf.rs's
//! module docs record that the executor's mechanism — the appended anchor
//! point, the reference-counted `-E`/`-X` enable, the per-interface
//! `-F states -i` flush — was never observed to actually bite, because no
//! sandbox had root. A disposable VM does, and running THIS code there (not a
//! re-implementation of it in the harness) is what makes a pass mean
//! something about the shipped helper.
//!
//! One process holds one executor for the whole session, because the enable
//! token lives in-process: a `scope` and a later `clear` must be the same
//! process or `-X` has nothing to release.
//!
//! Protocol, one command per line, one reply line each (`ok ...` / `err ...`):
//!
//! ```text
//! scope <port> <iface> [<iface>...]
//! clear
//! show
//! ```
//!
//! Refuses to start without `IPAURO_INSECURE_DEV=1`: it is an unauthenticated
//! way to rewrite pf, so it gets the same gate as the unauthenticated XPC
//! mode.

use std::io::{BufRead, Write};

use anyhow::{Result, bail};
use ipauro_proto::helper::INSECURE_DEV_ENV;

use crate::pf::{PfExecutor, PfctlExecutor};

pub const FLAG: &str = "--pf-console";

pub fn run(insecure_dev: bool) -> Result<()> {
    if !insecure_dev {
        bail!("{FLAG} drives pf with no authentication; refusing without {INSECURE_DEV_ENV}=1");
    }
    let pf = PfctlExecutor::new();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let reply = match handle(&pf, &line?) {
            Ok(msg) => format!("ok {msg}"),
            Err(e) => format!("err {}", format!("{e:#}").replace('\n', " | ")),
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    // stdin closed: leave pf as stock as we found it, exactly like fail-open.
    pf.clear_scopes()
}

fn handle(pf: &dyn PfExecutor, line: &str) -> Result<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["scope", port, ifaces @ ..] if !ifaces.is_empty() => {
            let ifaces: Vec<String> = ifaces.iter().map(|s| s.to_string()).collect();
            pf.scope_udp(port.parse()?, &ifaces)?;
            Ok(String::new())
        }
        ["clear"] => pf.clear_scopes().map(|()| String::new()),
        ["show"] => Ok(format!("{:?}", pf.scoped_ports())),
        _ => bail!("unknown command {line:?} (scope <port> <iface>... | clear | show)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(u16, Vec<String>)>>);
    impl PfExecutor for Recorder {
        fn scope_udp(&self, port: u16, allowed: &[String]) -> Result<()> {
            self.0.lock().unwrap().push((port, allowed.to_vec()));
            Ok(())
        }
        fn clear_scopes(&self) -> Result<()> {
            self.0.lock().unwrap().clear();
            Ok(())
        }
        fn scoped_ports(&self) -> Vec<(u16, Vec<String>)> {
            self.0.lock().unwrap().clone()
        }
    }

    #[test]
    fn scope_clear_and_show_reach_the_executor() {
        let pf = Recorder::default();
        handle(&pf, "scope 20808 en1 bridge0").unwrap();
        assert_eq!(handle(&pf, "show").unwrap(), r#"[(20808, ["en1", "bridge0"])]"#);
        handle(&pf, "clear").unwrap();
        assert_eq!(handle(&pf, "show").unwrap(), "[]");
    }

    #[test]
    fn malformed_commands_are_errors_not_scopes() {
        let pf = Recorder::default();
        assert!(handle(&pf, "scope 20808").is_err(), "a scope with no allowed interface would block the port everywhere");
        assert!(handle(&pf, "scope notaport en1").is_err());
        assert!(handle(&pf, "flush").is_err());
        assert!(pf.scoped_ports().is_empty());
    }

    #[test]
    fn refuses_without_the_insecure_dev_gate() {
        assert!(run(false).is_err());
    }
}
