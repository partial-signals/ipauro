//! CLI surface: `listen`, `beacon`, `check`.

use std::net::Ipv4Addr;

use clap::{Args, Parser, Subcommand};

/// Ableton Link's own UDP port — the port under test.
pub const DEFAULT_PORT: u16 = 20808;
/// Ableton Link's own IPv4 multicast group — the group under test.
pub const DEFAULT_GROUP: &str = "224.76.78.75";
/// Default spacing between beacon sends.
pub const DEFAULT_INTERVAL_MS: u64 = 500;
/// Default `check` run length.
pub const DEFAULT_CHECK_SECONDS: u64 = 5;

#[derive(Parser, Debug)]
#[command(
    name = "ipauro-probe",
    about = "R002-T8: probe macOS 15+ Local Network privacy gate for multicast \
             (Ableton Link's group/port) across execution contexts"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Join the multicast group and print one line per datagram received.
    Listen(ListenArgs),
    /// Send periodic beacon datagrams to the multicast group.
    Beacon(BeaconArgs),
    /// Beacon + listen simultaneously; report a gate-open / gate-denied verdict.
    Check(CheckArgs),
    /// Print macOS's recorded Local Network (multicast) decision per app.
    Grants(GrantsArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GrantsArgs {
    /// Only show records whose identifier or path contains this substring
    /// (case-insensitive).
    #[arg(long)]
    pub filter: Option<String>,
    /// Only show records with an explicit DENY; exit 4 if any exist.
    #[arg(long)]
    pub denied_only: bool,
}

/// Group/port/interface selection shared by every subcommand.
#[derive(Args, Debug, Clone)]
pub struct GroupArgs {
    /// Interface to use for multicast group membership / IP_MULTICAST_IF
    /// (default: let the OS pick).
    #[arg(long)]
    pub iface: Option<String>,
    /// UDP port (default matches Ableton Link).
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
    /// IPv4 multicast group (default matches Ableton Link's group).
    #[arg(long, default_value = DEFAULT_GROUP)]
    pub group: Ipv4Addr,
}

#[derive(Args, Debug, Clone)]
pub struct ListenArgs {
    #[command(flatten)]
    pub net: GroupArgs,
}

#[derive(Args, Debug, Clone)]
pub struct BeaconArgs {
    #[command(flatten)]
    pub net: GroupArgs,
    /// Milliseconds between beacons.
    #[arg(long, default_value_t = DEFAULT_INTERVAL_MS)]
    pub interval_ms: u64,
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    #[command(flatten)]
    pub net: GroupArgs,
    /// How long to run the combined beacon+listen check, in seconds.
    #[arg(long, default_value_t = DEFAULT_CHECK_SECONDS)]
    pub seconds: u64,
    /// Milliseconds between beacons.
    #[arg(long, default_value_t = DEFAULT_INTERVAL_MS)]
    pub interval_ms: u64,
    /// Interface for the BPF wire tap to watch (default: whatever `--iface`
    /// selects for multicast egress).
    ///
    /// Pointing the tap somewhere other than the egress interface is how you
    /// tell a real transmission apart from an in-kernel multicast loopback
    /// copy: macOS delivers the loopback copy via `lo0`, so
    /// `--iface en0 --tap-iface lo0` counts loopback copies while
    /// `--iface en0` (tap on `en0`) counts frames that actually left.
    #[arg(long)]
    pub tap_iface: Option<String>,
    /// Skip the BPF wire tap and report the weaker socket-only verdict.
    ///
    /// The tap needs an interface and read access to `/dev/bpf*` (root, or the
    /// `access_bpf` group). Without it, `check` cannot tell an open gate from
    /// loopback-only reception, nor an inbound denial from an outbound one.
    #[arg(long)]
    pub no_wire: bool,
}
