//! Bounded read of a staged `fleetd.tar.gz`.
//!
//! The reader accepts ustar entries only: regular files and directories. A symlink, a
//! hardlink, a device, a pax header or any other entry type refuses the whole archive, as do
//! absolute paths and `..` components, even on entries that are never written. Exactly one
//! entry named `fleetd` is copied out. Every byte taken from the decompressor counts against
//! a total cap, so a decompression bomb stops at the cap.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use flate2::read::GzDecoder;

use super::swap::SwapError;

const BLOCK: usize = 512;
const COPY_CHUNK: usize = 64 * 1024;

/// Most entries one archive may hold.
pub const MAX_TAR_ENTRIES: usize = 1024;

/// File name of the unpacked binary inside its version directory.
pub const BINARY_FILE: &str = "fleetd";

struct Counted<R> {
    inner: R,
    total: u64,
    cap: u64,
}

impl<R: Read> Counted<R> {
    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> Result<bool, SwapError> {
        let mut filled = 0;
        while filled < buf.len() {
            let rest = buf.get_mut(filled..).unwrap_or_default();
            let n = self.inner.read(rest).map_err(archive_io)?;
            if n == 0 {
                return if filled == 0 {
                    Ok(false)
                } else {
                    Err(SwapError::Archive("truncated"))
                };
            }
            filled += n;
            self.total = self.total.saturating_add(n as u64);
            if self.total > self.cap {
                return Err(SwapError::TooLarge);
            }
        }
        Ok(true)
    }

    fn read_block(&mut self, buf: &mut [u8; BLOCK]) -> Result<bool, SwapError> {
        self.read_exact_or_eof(buf)
    }

    fn skip(&mut self, mut len: u64) -> Result<(), SwapError> {
        let mut buf = vec![0u8; COPY_CHUNK];
        while len > 0 {
            let want = usize::try_from(len).map_or(COPY_CHUNK, |l| l.min(COPY_CHUNK));
            let part = buf.get_mut(..want).unwrap_or_default();
            if !self.read_exact_or_eof(part)? {
                return Err(SwapError::Archive("truncated"));
            }
            len -= want as u64;
        }
        Ok(())
    }

    fn copy_to(&mut self, mut len: u64, out: &mut File) -> Result<(), SwapError> {
        let mut buf = vec![0u8; COPY_CHUNK];
        while len > 0 {
            let want = usize::try_from(len).map_or(COPY_CHUNK, |l| l.min(COPY_CHUNK));
            let part = buf.get_mut(..want).unwrap_or_default();
            if !self.read_exact_or_eof(part)? {
                return Err(SwapError::Archive("truncated"));
            }
            out.write_all(part).map_err(SwapError::Io)?;
            len -= want as u64;
        }
        Ok(())
    }
}

fn archive_io(err: io::Error) -> SwapError {
    match err.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            SwapError::Archive("not a gzip stream")
        }
        _ => SwapError::Io(err),
    }
}

fn field(block: &[u8; BLOCK], from: usize, to: usize) -> &[u8] {
    let raw = block.get(from..to).unwrap_or_default();
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    raw.get(..end).unwrap_or_default()
}

fn octal(raw: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(raw).ok()?.trim_matches([' ', '\0']);
    if text.is_empty() {
        return Some(0);
    }
    if !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    u64::from_str_radix(text, 8).ok()
}

fn checksum_ok(block: &[u8; BLOCK]) -> bool {
    let stored = block.get(148..156).and_then(octal);
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*b)
            }
        })
        .sum();
    stored == Some(sum)
}

fn entry_path(block: &[u8; BLOCK]) -> Result<String, SwapError> {
    let name = std::str::from_utf8(field(block, 0, 100))
        .map_err(|_| SwapError::UnsafeEntry("name is not utf-8".to_owned()))?;
    let prefix = std::str::from_utf8(field(block, 345, 500))
        .map_err(|_| SwapError::UnsafeEntry("prefix is not utf-8".to_owned()))?;
    let full = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    if full.is_empty() || full.contains('\\') {
        return Err(SwapError::UnsafeEntry(full));
    }
    for component in Path::new(&full).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(SwapError::UnsafeEntry(full)),
        }
    }
    Ok(full)
}

fn is_binary(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|name| name == BINARY_FILE)
}

/// Copies the single `fleetd` entry of the gzip tar `archive` into `out`.
///
/// `max_binary` caps the entry size and `max_unpacked` caps every decompressed byte.
pub(super) fn extract(
    archive: File,
    out: &mut File,
    max_binary: u64,
    max_unpacked: u64,
) -> Result<(), SwapError> {
    let mut reader = Counted {
        inner: GzDecoder::new(archive),
        total: 0,
        cap: max_unpacked,
    };
    let mut found = false;
    let mut block = [0u8; BLOCK];
    for _ in 0..MAX_TAR_ENTRIES {
        if !reader.read_block(&mut block)? || block.iter().all(|b| *b == 0) {
            return if found {
                Ok(())
            } else {
                Err(SwapError::Archive("no fleetd entry"))
            };
        }
        if !checksum_ok(&block) {
            return Err(SwapError::Archive("header checksum"));
        }
        let path = entry_path(&block)?;
        let size = octal(field(&block, 124, 136)).ok_or(SwapError::Archive("size field"))?;
        match block.get(156).copied().unwrap_or(b'?') {
            b'0' | 0 => {
                let padded = size.div_ceil(BLOCK as u64).saturating_mul(BLOCK as u64);
                if is_binary(&path) {
                    if found {
                        return Err(SwapError::Archive("two fleetd entries"));
                    }
                    if size > max_binary {
                        return Err(SwapError::TooLarge);
                    }
                    reader.copy_to(size, out)?;
                    reader.skip(padded - size)?;
                    found = true;
                } else {
                    reader.skip(padded)?;
                }
            }
            b'5' => {
                if size != 0 {
                    return Err(SwapError::Archive("directory with data"));
                }
            }
            b'1' | b'2' => return Err(SwapError::UnsafeEntry(path)),
            _ => return Err(SwapError::Archive("unsupported entry type")),
        }
    }
    Err(SwapError::Archive("too many entries"))
}
