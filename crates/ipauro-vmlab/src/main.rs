//! `ipauro-vmlab run` on the host; `ipauro-vmlab guest` inside the VM.
//! See the library docs and `scripts/vm-l2.sh`.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ipauro_vmlab::cases::{CASES, GUEST_A, GUEST_B, Lab};
use ipauro_vmlab::lima::Lima;
use ipauro_vmlab::segment::Segment;

#[derive(Parser)]
#[command(about = "macOS-VM L2 test tier for IPAuRo (R009-T2)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host side: attach the segments, boot the guest, run the cases.
    Run {
        /// The `ipauro-helper` binary to exercise (its `--pf-console`).
        #[arg(long)]
        helper: PathBuf,
        /// The lima instance (created from `template:macos-26`).
        #[arg(long, default_value = "ipauro-vmlab")]
        instance: String,
        /// Run only this case.
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(CASES))]
        case: Option<String>,
    },
    /// Guest side: a Link-shaped endpoint (see `agent.rs`).
    Guest {
        #[arg(long = "iface", required = true)]
        ifaces: Vec<String>,
        #[arg(long)]
        unicast: Vec<Ipv4Addr>,
        #[arg(long, default_value_t = 5.0)]
        seconds: f64,
        #[arg(long, default_value_t = 50)]
        interval_ms: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Guest { ifaces, unicast, seconds, interval_ms } => {
            ipauro_vmlab::agent::run(&ifaces, &unicast, seconds, Duration::from_millis(interval_ms))
        }
        Cmd::Run { helper, instance, case } => run(helper, instance, case),
    }
}

fn run(helper: PathBuf, instance: String, case: Option<String>) -> Result<()> {
    let helper = helper.canonicalize().with_context(|| format!("helper binary {}", helper.display()))?;
    let me = std::env::current_exe()?;
    let lima = Lima { instance };
    match lima.status()?.as_str() {
        "" => bail!(
            "no lima instance {:?}. Create it once with:\n  limactl start --name={} --tty=false template:macos-26\n(downloads the macOS IPSW, ~17 GB)",
            lima.instance,
            lima.instance
        ),
        "Running" => {
            eprintln!("stopping {} to re-attach its segment NICs", lima.instance);
            lima.stop()?;
        }
        _ => {}
    }

    // Short, fixed paths: sun_path is 104 bytes on macOS.
    let dir = PathBuf::from("/tmp/ipauro-vmlab");
    std::fs::create_dir_all(&dir)?;
    let a = Segment::listen("a", &dir.join("a.sock"))?;
    let b = Segment::listen("b", &dir.join("b.sock"))?;
    lima.ensure_headless()?;
    lima.set_networks(&[(&a.path, GUEST_A), (&b.path, GUEST_B)])?;

    let outcome = (|| -> Result<_> {
        eprintln!("booting {}", lima.instance);
        lima.start()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !(a.is_connected() && b.is_connected()) {
            if Instant::now() > deadline {
                bail!("the guest never attached to both segment sockets (lima `socket:` networks)");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        lima.ensure_sudo()?;
        let lab = Lab::new(lima.clone(), a.clone(), b.clone())?;
        lab.install(&me, &helper)?;
        lab.run(case.as_deref())
    })();

    // Always detach: a stopped instance left pointing at dead sockets cannot
    // be started by hand.
    let _ = lima.stop();
    let _ = lima.set_networks(&[]);
    a.shutdown();
    b.shutdown();

    let report = outcome?;
    println!("\n{} passed, {} failed", report.passed, report.failed);
    if report.failed > 0 {
        bail!("{} L2 check(s) failed", report.failed);
    }
    Ok(())
}
