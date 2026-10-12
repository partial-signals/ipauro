//! ADM-OSC v1.0 → object state. ADM-OSC is the open OSC grammar that object
//! editors, DAW plug-ins and live renderers (L-ISA, SPAT Revolution,
//! Holophonix, d&b Soundscape, …) use to stream object positions; see
//! <https://github.com/immersive-audio-live/ADM-OSC> (MIT). Default UDP
//! port 4001.
//!
//! This module only interprets an already-decoded OSC message
//! (address + arguments). Packet decoding belongs with whichever IPAuRo
//! adapter owns the socket.

use serde::Serialize;

use crate::coords::{Aed, Vec3};

/// A decoded OSC argument.
#[derive(Debug, Clone, PartialEq)]
pub enum OscArg {
    Float(f32),
    Int(i32),
    Str(String),
}

impl OscArg {
    fn f(&self) -> Option<f32> {
        match self {
            OscArg::Float(v) => Some(*v),
            OscArg::Int(v) => Some(*v as f32),
            OscArg::Str(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ObjectUpdate {
    Xyz(Vec3),
    Xy(f32, f32),
    X(f32),
    Y(f32),
    Z(f32),
    Aed(Aed),
    Azimuth(f32),
    Elevation(f32),
    Distance(f32),
    /// Horizontal extent 0..1.
    Width(f32),
    /// Linear gain, 1.0 = unity.
    Gain(f32),
    Mute(bool),
    Name(String),
    /// Message without arguments: a query for the current value.
    Query(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ObjectMessage {
    /// ADM-OSC object number (1-based).
    pub object: u32,
    pub update: ObjectUpdate,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AdmOscError {
    #[error("not an /adm/obj/<n>/<param> address: {0}")]
    Address(String),
    #[error("unknown ADM-OSC object parameter: {0}")]
    Parameter(String),
    #[error("wrong arguments for {0}")]
    Arguments(String),
}

/// Interprets one ADM-OSC object message. Wildcard addresses
/// (`/adm/obj/*/gain`) need expanding by the caller, which knows the
/// object set.
pub fn parse(address: &str, args: &[OscArg]) -> Result<ObjectMessage, AdmOscError> {
    let mut parts = address.trim_start_matches('/').split('/');
    let (Some("adm"), Some("obj"), Some(n), Some(param), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(AdmOscError::Address(address.into()));
    };
    let object: u32 = n
        .parse()
        .map_err(|_| AdmOscError::Address(address.into()))?;
    if object == 0 {
        return Err(AdmOscError::Address(address.into()));
    }
    if args.is_empty() {
        return Ok(ObjectMessage {
            object,
            update: ObjectUpdate::Query(param.into()),
        });
    }
    let bad = || AdmOscError::Arguments(address.into());
    let fl = |i: usize| args.get(i).and_then(OscArg::f).ok_or_else(bad);
    let update = match param {
        "xyz" => ObjectUpdate::Xyz(Vec3::new(fl(0)?, fl(1)?, fl(2)?)),
        "xy" => ObjectUpdate::Xy(fl(0)?, fl(1)?),
        "x" => ObjectUpdate::X(fl(0)?),
        "y" => ObjectUpdate::Y(fl(0)?),
        "z" => ObjectUpdate::Z(fl(0)?),
        "aed" => ObjectUpdate::Aed(Aed {
            azimuth: fl(0)?,
            elevation: fl(1)?,
            distance: fl(2)?,
        }),
        "azim" => ObjectUpdate::Azimuth(fl(0)?),
        "elev" => ObjectUpdate::Elevation(fl(0)?),
        "dist" => ObjectUpdate::Distance(fl(0)?),
        "w" => ObjectUpdate::Width(fl(0)?),
        "gain" => ObjectUpdate::Gain(fl(0)?),
        "mute" => ObjectUpdate::Mute(fl(0)? != 0.0),
        "name" => match &args[0] {
            OscArg::Str(s) => ObjectUpdate::Name(s.clone()),
            _ => return Err(bad()),
        },
        other => return Err(AdmOscError::Parameter(other.into())),
    };
    Ok(ObjectMessage { object, update })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_examples() {
        let m = parse(
            "/adm/obj/4/xyz",
            &[OscArg::Float(-0.9), OscArg::Float(0.15), OscArg::Float(0.7)],
        )
        .unwrap();
        assert_eq!(m.object, 4);
        assert_eq!(m.update, ObjectUpdate::Xyz(Vec3::new(-0.9, 0.15, 0.7)));
        let m = parse("/adm/obj/2/mute", &[OscArg::Int(1)]).unwrap();
        assert_eq!(m.update, ObjectUpdate::Mute(true));
        let m = parse("/adm/obj/1/name", &[OscArg::Str("kickdrum".into())]).unwrap();
        assert_eq!(m.update, ObjectUpdate::Name("kickdrum".into()));
        assert_eq!(
            parse("/adm/obj/4/xyz", &[]).unwrap().update,
            ObjectUpdate::Query("xyz".into())
        );
    }

    #[test]
    fn rejects_malformed() {
        assert!(matches!(
            parse("/adm/lis/xyz", &[]),
            Err(AdmOscError::Address(_))
        ));
        assert!(matches!(
            parse("/adm/obj/0/x", &[OscArg::Float(0.0)]),
            Err(AdmOscError::Address(_))
        ));
        assert!(matches!(
            parse("/adm/obj/1/foo", &[OscArg::Float(0.0)]),
            Err(AdmOscError::Parameter(_))
        ));
        assert!(matches!(
            parse("/adm/obj/1/xyz", &[OscArg::Float(0.0)]),
            Err(AdmOscError::Arguments(_))
        ));
    }
}
