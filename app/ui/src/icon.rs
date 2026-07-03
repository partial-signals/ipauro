//! Programmatic icon generation: a small colored-circle RGBA buffer, shared
//! by the tray icon and the window icon. No binary assets — per the theming
//! pass (`theme.rs`), this is scaffolding that real artwork replaces later.

/// The tray/window icon's placeholder accent color (straight RGBA).
pub const ACCENT: [u8; 4] = [58, 143, 226, 255];

/// Render a filled circle of `color` (straight, unmultiplied alpha) into a
/// `size` × `size` RGBA8 buffer, row-major, 4 bytes per pixel. `size` should
/// be a multiple of 4 for `egui::IconData`'s convention; `tray_icon::Icon`
/// has no such requirement.
pub fn circle_rgba(size: u32, color: [u8; 4]) -> Vec<u8> {
    let mut buf = vec![0_u8; (size * size * 4) as usize];
    let center = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 / 2.0 - 1.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let idx = ((y * size + x) * 4) as usize;
            if dx * dx + dy * dy <= radius * radius {
                buf[idx..idx + 4].copy_from_slice(&color);
            }
            // else: leave fully transparent (buffer is zero-initialized).
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_is_correctly_sized() {
        let size = 32;
        let buf = circle_rgba(size, [1, 2, 3, 4]);
        assert_eq!(buf.len(), (size * size * 4) as usize);
    }

    #[test]
    fn center_pixel_is_opaque_and_colored() {
        let size = 16;
        let color = [10, 20, 30, 255];
        let buf = circle_rgba(size, color);
        let center = (size / 2) as usize;
        let idx = (center * size as usize + center) * 4;
        assert_eq!(&buf[idx..idx + 4], &color);
    }

    #[test]
    fn corner_pixel_is_transparent() {
        let size = 16;
        let buf = circle_rgba(size, [10, 20, 30, 255]);
        assert_eq!(&buf[0..4], &[0, 0, 0, 0]);
    }
}
