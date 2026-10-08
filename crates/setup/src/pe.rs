// SPDX-License-Identifier: MIT
//! Bounded PE checks. These reject obvious incompatibilities, not certify HVCI.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    pub nx: bool,
    pub page_aligned: bool,
    pub writable_executable: bool,
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("Truncated image")?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("Truncated image")?
            .try_into()
            .unwrap(),
    ))
}
/// Read the headers needed to reject incompatible executable-memory flags.
/// These checks supplement Windows trust; they do not certify HVCI support.
pub fn inspect(bytes: &[u8]) -> Result<Image, &'static str> {
    if bytes.get(..2) != Some(b"MZ") {
        return Err("Not a PE image");
    }
    let base = u32_at(bytes, 0x3c)? as usize;
    if base > bytes.len().saturating_sub(24) || bytes.get(base..base + 4) != Some(b"PE\0\0") {
        return Err("Invalid PE header");
    }
    if u16_at(bytes, base + 4)? != 0x8664 {
        return Err("Driver must be x64");
    }
    let count = u16_at(bytes, base + 6)? as usize;
    let optional_len = u16_at(bytes, base + 20)? as usize;
    if optional_len < 112 || u16_at(bytes, base + 24)? != 0x20b {
        return Err("Invalid PE32+ optional header");
    }
    if u16_at(bytes, base + 24 + 68)? != 1 {
        return Err("Not a native driver image");
    }
    let section_base = base + 24 + optional_len;
    // Bound the complete section table before walking its fixed-size entries.
    let section_bytes = count.checked_mul(40).ok_or("Section table overflow")?;
    let table = bytes
        .get(
            section_base
                ..section_base
                    .checked_add(section_bytes)
                    .ok_or("Section table overflow")?,
        )
        .ok_or("Truncated section table")?;
    let mut wx = false;
    for section in table.as_chunks::<40>().0 {
        let flags = u32_at(section, 36)?;
        wx |= flags & 0xa0000000 == 0xa0000000;
    }
    Ok(Image {
        nx: u16_at(bytes, base + 24 + 70)? & 0x100 != 0,
        page_aligned: u32_at(bytes, base + 24 + 32)? >= 4096,
        writable_executable: wx,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; 512];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c] = 64;
        b[64..68].copy_from_slice(b"PE\0\0");
        b[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        b[70] = 1;
        b[84] = 112;
        b[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        b[120..124].copy_from_slice(&4096u32.to_le_bytes());
        b[156] = 1;
        b[158..160].copy_from_slice(&0x100u16.to_le_bytes());
        b
    }
    #[test]
    fn pe_bounds_and_architecture() {
        let mut b = image();
        assert_eq!(
            inspect(&b).unwrap(),
            Image {
                nx: true,
                page_aligned: true,
                writable_executable: false
            }
        );
        for n in 0..240 {
            assert!(inspect(&b[..n]).is_err());
        }
        b[68] = 0;
        assert!(inspect(&b).is_err());
    }
    #[test]
    fn executable_writable_is_reported() {
        let mut b = image();
        b[236..240].copy_from_slice(&0xa0000000u32.to_le_bytes());
        assert!(inspect(&b).unwrap().writable_executable);
    }
    #[test]
    fn arbitrary_inputs_do_not_panic() {
        for n in 0..1024 {
            let b = vec![0xff; n];
            let _ = inspect(&b);
        }
    }
}
