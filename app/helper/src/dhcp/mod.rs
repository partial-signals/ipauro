//! In-process DHCP responder (`ServeDhcp`/`StopDhcp`, ticket R005-T6) —
//! NEVER `/etc/bootpd.plist` (that config is shared with Internet Sharing
//! and macOS updates fight over it; the prototype's `enable-dhcp.sh` is
//! PoC-only). Split into:
//! - [`packet`]: hand-rolled RFC 2131 codec (encode/decode + malformed
//!   rejection), fully unit-tested.
//! - [`lease`]: a static in-memory lease table over the pool.
//! - [`responder`]: pure DISCOVER->OFFER / REQUEST->ACK logic — the ONLY
//!   place outgoing options are assembled, guaranteeing no router/gateway
//!   option (option 3) is ever emitted.
//! - [`server`]: the raw-socket thread binding `:67` on the bridge only,
//!   gluing the above together. Not unit-testable without root + a real
//!   bridge interface (bench-verified later).

mod lease;
mod packet;
mod responder;
mod server;

pub use server::{DhcpExecutor, RawSocketDhcpResponder};
