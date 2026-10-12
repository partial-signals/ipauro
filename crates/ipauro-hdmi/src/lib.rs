//! HDMI audio sink capabilities and host encoded-output probing (W002).
//!
//! - [`sad`], [`edid`], [`eld`]: parse what the sink (TV/AVR) advertises,
//!   including the CTA-861 bits that say whether it decodes DD+ JOC (Atmos
//!   in E-AC-3) and MAT object-audio PCM, and whether MAT PCM needs a
//!   source-side hash.
//! - [`caps`]: reduce that to the Atmos carriers the sink accepts.
//! - [`platform`]: what the host OS exposes for encoded output (Core Audio
//!   on macOS, ALSA/DRM on Linux). It reports what the OS *lists*, not what
//!   reaches the wire; the passthrough test and an AVR display settle that.

pub mod caps;
pub mod edid;
pub mod eld;
pub mod platform;
pub mod sad;

#[cfg(target_os = "macos")]
pub mod coreaudio;
