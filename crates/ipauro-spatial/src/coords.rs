//! Coordinate conventions.
//!
//! **IPAuRo canonical = ADM cartesian** (ITU-R BS.2076 `cartesian="1"`),
//! which ADM-OSC v1.0 uses unchanged. It's a room-normalised cube,
//! listener at the origin:
//!
//! | axis | −1 | +1 |
//! |---|---|---|
//! | x | left wall | right wall |
//! | y | back wall | front wall |
//! | z | floor (bottom) | ceiling (top); 0 = ear-height plane |
//!
//! Positions are *room-relative*, not metric: (1, 1, 0) is the front-right
//! corner whatever the room's size. A renderer maps them to its speakers.
//!
//! Neighbouring conventions, and how sure we are of each mapping:
//! - **ADM-OSC** `/xyz`: identical (spec quick reference, v1.0). Confirmed.
//! - **ADM-OSC / ADM polar** (`/aed`): azimuth 0° = front, **positive =
//!   left**, elevation +90° = up, distance 0..1. ADM's normative
//!   polar↔cartesian mapping (BS.2127 §10) warps sphere to cube and is **not**
//!   spherical trigonometry (the ADM-OSC test tool's own aed/xyz pairs
//!   disagree with sin/cos). [`Aed::to_cartesian_spherical`] is the plain
//!   spherical version, good for demos and labelled as such.
//! - **noisetable** (`@speaker[az]`, `SpatialPositionWire::to_angular_degrees`):
//!   the cartesian axes are the same, but its azimuth is **positive = right**
//!   (`@speaker[-30] @speaker[30]` is a stereo pair). [`Aed`] follows ADM
//!   (positive = left). The proposed shared format (noisetable W256) keeps
//!   angles off the wire for exactly this reason.
//! - **Dolby OAMD room coordinates** (ETSI TS 103 420): x 0..1 left→right,
//!   y 0..1 **front→back**, z −1..1 (sign + magnitude; 0 = horizontal
//!   plane). This comes from open implementations of the spec, not from
//!   reading the ETSI text (W002 hypothesis H-C1), so treat
//!   [`to_oamd_room`] as provisional until checked against the spec.

use serde::{Deserialize, Serialize};

/// A position in IPAuRo canonical (ADM cartesian) coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const FRONT_CENTER: Vec3 = Vec3 {
        x: 0.0,
        y: 1.0,
        z: 0.0,
    };
    pub const FRONT_LEFT: Vec3 = Vec3 {
        x: -1.0,
        y: 1.0,
        z: 0.0,
    };
    pub const FRONT_RIGHT: Vec3 = Vec3 {
        x: 1.0,
        y: 1.0,
        z: 0.0,
    };
    pub const REAR_LEFT: Vec3 = Vec3 {
        x: -1.0,
        y: -1.0,
        z: 0.0,
    };
    pub const REAR_RIGHT: Vec3 = Vec3 {
        x: 1.0,
        y: -1.0,
        z: 0.0,
    };
    pub const OVERHEAD: Vec3 = Vec3 {
        x: 0.0,
        y: 0.0,
        z: 1.0,
    };

    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    /// Clamps every axis to the [-1, 1] room cube.
    pub fn clamped(self) -> Self {
        Self {
            x: self.x.clamp(-1.0, 1.0),
            y: self.y.clamp(-1.0, 1.0),
            z: self.z.clamp(-1.0, 1.0),
        }
    }

    /// A point on the horizontal circle of radius `r` at `turns` (0 = front,
    /// increasing counter-clockwise seen from above, i.e. toward the left,
    /// matching ADM azimuth).
    pub fn orbit(turns: f32, r: f32, z: f32) -> Self {
        let a = turns * std::f32::consts::TAU;
        Self {
            x: -a.sin() * r,
            y: a.cos() * r,
            z,
        }
    }
}

/// ADM / ADM-OSC polar position.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Aed {
    /// Degrees, 0 = front, positive = left, −180..180.
    pub azimuth: f32,
    /// Degrees, 0 = horizontal, +90 = up.
    pub elevation: f32,
    /// Normalised, 1 = reference sphere.
    pub distance: f32,
}

impl Aed {
    /// Plain spherical → cartesian. Not BS.2127's sphere-to-cube mapping;
    /// see the module docs.
    pub fn to_cartesian_spherical(self) -> Vec3 {
        let (az, el) = (self.azimuth.to_radians(), self.elevation.to_radians());
        Vec3 {
            x: -az.sin() * el.cos() * self.distance,
            y: az.cos() * el.cos() * self.distance,
            z: el.sin() * self.distance,
        }
    }
}

/// Canonical → Dolby OAMD room coordinates `(x 0..1 L→R, y 0..1 F→B,
/// z −1..1)`. **Provisional** (H-C1).
pub fn to_oamd_room(v: Vec3) -> (f32, f32, f32) {
    let v = v.clamped();
    ((v.x + 1.0) / 2.0, (1.0 - v.y) / 2.0, v.z)
}

/// Inverse of [`to_oamd_room`]. **Provisional** (H-C1).
pub fn from_oamd_room(x: f32, y: f32, z: f32) -> Vec3 {
    Vec3 {
        x: x * 2.0 - 1.0,
        y: 1.0 - y * 2.0,
        z,
    }
    .clamped()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: Vec3, b: Vec3) -> bool {
        (a.x - b.x).abs() < 1e-5 && (a.y - b.y).abs() < 1e-5 && (a.z - b.z).abs() < 1e-5
    }

    #[test]
    fn positive_azimuth_is_left() {
        let left = Aed {
            azimuth: 90.0,
            elevation: 0.0,
            distance: 1.0,
        }
        .to_cartesian_spherical();
        assert!(close(left, Vec3::new(-1.0, 0.0, 0.0)));
        let up = Aed {
            azimuth: 0.0,
            elevation: 90.0,
            distance: 1.0,
        }
        .to_cartesian_spherical();
        assert!(close(up, Vec3::OVERHEAD));
        assert!(close(
            Vec3::orbit(0.25, 1.0, 0.0),
            Vec3::new(-1.0, 0.0, 0.0)
        ));
    }

    #[test]
    fn oamd_room_round_trip_and_landmarks() {
        assert_eq!(to_oamd_room(Vec3::FRONT_LEFT), (0.0, 0.0, 0.0));
        assert_eq!(to_oamd_room(Vec3::REAR_RIGHT), (1.0, 1.0, 0.0));
        for v in [
            Vec3::FRONT_CENTER,
            Vec3::REAR_LEFT,
            Vec3::OVERHEAD,
            Vec3::new(0.3, -0.2, 0.5),
        ] {
            let (x, y, z) = to_oamd_room(v);
            assert!(close(from_oamd_room(x, y, z), v));
        }
    }
}
