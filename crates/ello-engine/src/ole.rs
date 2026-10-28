//! Minimal OLE2 Compound File (CFB) reader and VBA macro source extraction.
//!
//! This is just enough of MS-CFB / MS-OVBA to pull decompressed macro source
//! out of legacy Office documents (`.doc`, `.xls`, `.ppt`) and the `vbaProject.bin`
//! found inside OOXML (`.docm`, `.xlsm`) archives, so the string heuristics can
//! inspect it. It parses untrusted input, so every offset is bounds-checked and
//! chain walking is capped to avoid loops.

const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
const MAX_SECTORS: usize = 1 << 22; // guards against malformed FATs

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

struct Cfb<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    dir: Vec<DirEntry>,
    mini_stream: Vec<u8>,
    mini_cutoff: u32,
}

#[derive(Clone)]
struct DirEntry {
    name: String,
    kind: u8, // 1=storage, 2=stream, 5=root
    start: u32,
    size: u64,
}

impl<'a> Cfb<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if !data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
            return None;
        }
        let sector_shift = u16le(data, 30)?;
        let mini_shift = u16le(data, 32)?;
        if !(7..=12).contains(&sector_shift) || mini_shift != 6 {
            return None;
        }
        let sector_size = 1usize << sector_shift;
        let mini_sector_size = 1usize << mini_shift;
        let num_fat_sectors = u32le(data, 44)? as usize;
        let dir_start = u32le(data, 48)?;
        let mini_cutoff = u32le(data, 56)?;
        let mini_fat_start = u32le(data, 60)?;
        let num_mini_fat = u32le(data, 64)? as usize;
        let difat_start = u32le(data, 68)?;
        let num_difat = u32le(data, 72)? as usize;

        let sector = |idx: u32, data: &'a [u8]| -> Option<&'a [u8]> {
            let off = (idx as usize + 1).checked_mul(sector_size)?;
            data.get(off..off.checked_add(sector_size)?)
        };

        // Collect FAT sector locations from the header DIFAT (first 109) and
        // any DIFAT sectors.
        let mut fat_sectors = Vec::new();
        for i in 0..109 {
            if let Some(v) = u32le(data, 76 + i * 4) {
                if v != FREESECT && v != ENDOFCHAIN {
                    fat_sectors.push(v);
                }
            }
        }
        let mut difat = difat_start;
        let mut guard = 0;
        while difat != ENDOFCHAIN && difat != FREESECT && guard < MAX_SECTORS && guard <= num_difat
        {
            let sec = sector(difat, data)?;
            let entries = sector_size / 4 - 1;
            for i in 0..entries {
                if let Some(v) = u32le(sec, i * 4) {
                    if v != FREESECT && v != ENDOFCHAIN {
                        fat_sectors.push(v);
                    }
                }
            }
            difat = u32le(sec, entries * 4)?;
            guard += 1;
        }
        fat_sectors.truncate(num_fat_sectors.max(fat_sectors.len().min(MAX_SECTORS)));

        let mut fat = Vec::new();
        for fs in fat_sectors {
            let sec = sector(fs, data)?;
            for i in 0..sector_size / 4 {
                fat.push(u32le(sec, i * 4)?);
            }
            if fat.len() > MAX_SECTORS {
                return None;
            }
        }

        let walk = |start: u32, fat: &[u32]| -> Vec<u32> {
            let mut chain = Vec::new();
            let mut cur = start;
            let mut g = 0;
            while cur != ENDOFCHAIN
                && cur != FREESECT
                && (cur as usize) < fat.len()
                && g < MAX_SECTORS
            {
                chain.push(cur);
                cur = fat[cur as usize];
                g += 1;
            }
            chain
        };

        let read_chain = |start: u32, fat: &[u32], data: &'a [u8]| -> Vec<u8> {
            let mut out = Vec::new();
            for idx in walk(start, fat) {
                if let Some(s) = sector(idx, data) {
                    out.extend_from_slice(s);
                }
            }
            out
        };

        // Directory.
        let dir_bytes = read_chain(dir_start, &fat, data);
        let mut dir = Vec::new();
        let mut off = 0;
        while off + 128 <= dir_bytes.len() {
            let e = &dir_bytes[off..off + 128];
            let kind = e[66];
            let name_len = u16le(e, 64).unwrap_or(0) as usize;
            if (1..=5).contains(&kind) && (2..=64).contains(&name_len) {
                let utf16: Vec<u16> = (0..(name_len / 2 - 1))
                    .filter_map(|i| u16le(e, i * 2))
                    .collect();
                dir.push(DirEntry {
                    name: String::from_utf16_lossy(&utf16),
                    kind,
                    start: u32le(e, 116).unwrap_or(ENDOFCHAIN),
                    size: u32le(e, 120).unwrap_or(0) as u64
                        | ((u32le(e, 124).unwrap_or(0) as u64) << 32),
                });
            }
            off += 128;
        }

        // Mini FAT + mini stream (held in the root entry's chain).
        let mut mini_fat = Vec::new();
        for idx in walk(mini_fat_start, &fat)
            .into_iter()
            .take(num_mini_fat.clamp(1, MAX_SECTORS))
        {
            if let Some(s) = sector(idx, data) {
                for i in 0..sector_size / 4 {
                    if let Some(v) = u32le(s, i * 4) {
                        mini_fat.push(v);
                    }
                }
            }
        }
        let mini_stream = dir
            .iter()
            .find(|d| d.kind == 5)
            .map(|root| read_chain(root.start, &fat, data))
            .unwrap_or_default();

        Some(Cfb {
            data,
            sector_size,
            mini_sector_size,
            fat,
            mini_fat,
            dir,
            mini_stream,
            mini_cutoff,
        })
    }

    fn read_stream(&self, e: &DirEntry) -> Vec<u8> {
        let mut out = Vec::new();
        if e.size < self.mini_cutoff as u64 {
            let mut cur = e.start;
            let mut g = 0;
            while cur != ENDOFCHAIN
                && cur != FREESECT
                && (cur as usize) < self.mini_fat.len()
                && g < MAX_SECTORS
            {
                let off = cur as usize * self.mini_sector_size;
                if let Some(s) = self.mini_stream.get(off..off + self.mini_sector_size) {
                    out.extend_from_slice(s);
                }
                cur = self.mini_fat[cur as usize];
                g += 1;
            }
        } else {
            let mut cur = e.start;
            let mut g = 0;
            while cur != ENDOFCHAIN
                && cur != FREESECT
                && (cur as usize) < self.fat.len()
                && g < MAX_SECTORS
            {
                let off = (cur as usize + 1) * self.sector_size;
                if let Some(s) = self.data.get(off..off + self.sector_size) {
                    out.extend_from_slice(s);
                }
                cur = self.fat[cur as usize];
                g += 1;
            }
        }
        out.truncate(e.size as usize);
        out
    }
}

/// Decompresses an MS-OVBA CompressedContainer starting at `data[0] == 0x01`.
/// Returns `None` on malformed input.
fn decompress_ovba(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() != Some(&0x01) {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 1;
    while pos + 1 < data.len() {
        let header = u16le(data, pos)? as usize;
        pos += 2;
        let chunk_size = (header & 0x0FFF) + 3;
        let compressed = header & 0x8000 != 0;
        let chunk_end = (pos + chunk_size - 2).min(data.len());
        if !compressed {
            out.extend_from_slice(data.get(pos..pos + 4096)?);
            pos += 4096;
            continue;
        }
        let decomp_start = out.len();
        while pos < chunk_end {
            let flags = *data.get(pos)?;
            pos += 1;
            for bit in 0..8 {
                if pos >= chunk_end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(*data.get(pos)?);
                    pos += 1;
                } else {
                    let token = u16le(data, pos)?;
                    pos += 2;
                    // CopyTokenHelp (MS-OVBA 2.4.1.3.19.3): the split between
                    // offset and length bits depends on how much of this chunk
                    // has been produced so far.
                    let diff = out.len() - decomp_start;
                    let bit_count = if diff <= 1 {
                        4
                    } else {
                        (usize::BITS - (diff - 1).leading_zeros()).max(4) as u16
                    };
                    let len_mask = 0xFFFFu16 >> bit_count;
                    let len = (token & len_mask) as usize + 3;
                    let offset = ((token >> (16 - bit_count)) as usize) + 1;
                    if offset > out.len() - decomp_start {
                        return None;
                    }
                    let src_start = out.len() - offset;
                    for i in 0..len {
                        let b = out[src_start + i];
                        out.push(b);
                    }
                }
            }
        }
        pos = chunk_end;
        if out.len() > 64 * 1024 * 1024 {
            break;
        }
    }
    Some(out)
}

/// Extracts decompressed VBA macro source from an OLE/CFB blob (a legacy Office
/// file or a `vbaProject.bin`). Returns concatenated module source, or `None`
/// when the blob is not CFB or holds no recoverable macro code.
pub fn extract_vba(data: &[u8]) -> Option<String> {
    let cfb = Cfb::parse(data)?;
    let mut source = String::new();
    let entries: Vec<DirEntry> = cfb.dir.iter().filter(|e| e.kind == 2).cloned().collect();
    for e in entries {
        if e.size == 0 || e.size > 32 * 1024 * 1024 {
            continue;
        }
        let stream = cfb.read_stream(&e);
        // Module streams hold performance-cache bytes followed by the
        // compressed source container. Try decompressing at each 0x01 marker.
        for start in 0..stream.len().min(1 << 20) {
            if stream[start] != 0x01 {
                continue;
            }
            if let Some(dec) = decompress_ovba(&stream[start..]) {
                if dec.windows(12).any(|w| w == b"Attribute VB") {
                    source.push_str(&String::from_utf8_lossy(&dec));
                    source.push('\n');
                    break;
                }
            }
        }
    }
    if source.is_empty() {
        None
    } else {
        Some(source)
    }
}

/// True if the CFB blob contains a VBA project storage (fast pre-check).
pub fn has_vba_project(data: &[u8]) -> bool {
    match Cfb::parse(data) {
        Some(cfb) => cfb.dir.iter().any(|e| e.name.eq_ignore_ascii_case("VBA")),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_copy_token() {
        // Hand-built compressed container encoding "ABCABC": three literals
        // then a CopyToken(offset=3, length=3). Chunk header 0xB005 marks a
        // compressed chunk of size 8 (incl. the 2-byte header).
        let blob: &[u8] = &[0x01, 0x05, 0xB0, 0x08, b'A', b'B', b'C', 0x00, 0x20];
        assert_eq!(decompress_ovba(blob).unwrap(), b"ABCABC");
    }

    #[test]
    fn decompress_all_literals() {
        // Flag byte 0x00 => eight literal bytes follow.
        let blob: &[u8] = &[
            0x01, 0x08, 0xB0, 0x00, b'm', b'a', b'c', b'r', b'o', b'!', b'!', b'!',
        ];
        assert_eq!(decompress_ovba(blob).unwrap(), b"macro!!!");
    }

    #[test]
    fn uncompressed_chunk_passthrough() {
        let mut blob = vec![0x01u8];
        let payload = vec![b'Z'; 4096];
        blob.extend_from_slice(&0x0FFFu16.to_le_bytes()); // raw chunk, size 4096
        blob.extend_from_slice(&payload);
        let out = decompress_ovba(&blob).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn rejects_non_cfb() {
        assert!(extract_vba(b"not an ole file").is_none());
        assert!(!has_vba_project(b"MZ\x90\x00"));
    }
}
