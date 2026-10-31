//! ipauro-vmlab — the macOS-VM L2 test tier (W001 §9, R009-T2).
//!
//! One real macOS guest (lima, `vmType: vz`) is the device under test: its
//! kernel `if_bridge`, its pf, its IGMP. Its extra NICs are not attached to a
//! vmnet switch but to unix sockets THIS process owns ([`segment`]), so every
//! wire-level observation is taken outside the kernel being tested, and the
//! other hosts on each segment are emulated peers rather than more VMs —
//! which also makes Apple's two-VMs-per-host licensing cap irrelevant to the
//! cases here. The same binary runs inside the guest as the Link-shaped
//! endpoint ([`agent`]).
//!
//! What this tier cannot see, and therefore leaves to the hardware runbook
//! (R009-T3): USB-NCM enumeration, data-role negotiation, cable quality,
//! accessory approval, and the member-unplug teardown (a socket NIC cannot be
//! hot-removed the way a USB gadget is).
//!
//! @arch:see(.yah/docs/working/W001-ipauro-plan.md)
//! @arch:see(.yah/docs/architecture/A002-ipauro-findings.md)

pub mod agent;
pub mod cases;
pub mod frame;
pub mod lima;
pub mod segment;
