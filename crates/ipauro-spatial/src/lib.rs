//! Object-audio model for IPAuRo: the `Object{pos, gain, t}` channel role of
//! the A004 canonical stream, made concrete.
//!
//! - [`coords`]: the one coordinate system IPAuRo uses internally, and the
//!   conversions to and from the conventions around it (ADM-OSC, Dolby's
//!   room coordinates).
//! - [`adm_osc`]: maps ADM-OSC v1.0 messages (DAWs, object editors) onto
//!   object state.
//! - [`encoder`]: the contract a carrier encoder (DD+ JOC, MAT object PCM)
//!   implements. Today every carrier returns an explicit `Unimplemented`
//!   error that says why. Nothing here produces placeholder bytes that could
//!   pass for a valid stream.

pub mod adm_osc;
pub mod coords;
pub mod encoder;

pub use coords::Vec3;
pub use encoder::{Carrier, EncodeError, ObjectBlock, ObjectEncoder, ObjectState};
