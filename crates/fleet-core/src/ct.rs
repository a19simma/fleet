use std::hint::black_box;

const MIN_SCAN: usize = 256;

/// Compares two byte strings without branching on their contents.
///
/// The scan covers `max(a.len(), b.len(), 256)` bytes, reading missing bytes as zero, so
/// the time depends on the longer length and not on where the first difference sits. The
/// lengths fold into the result, so a string never equals its zero padded extension.
/// Lengths themselves are not hidden.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let scan = a.len().max(b.len()).max(MIN_SCAN);
    let mut diff = (a.len() ^ b.len()) as u64;
    for i in 0..scan {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= u64::from(x ^ y);
    }
    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_inputs_match() {
        assert!(constant_time_eq(b"Bearer secret", b"Bearer secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn differing_inputs_do_not_match() {
        assert!(!constant_time_eq(b"Bearer secret", b"Bearer secreu"));
        assert!(!constant_time_eq(b"a", b"b"));
    }

    #[test]
    fn length_mismatch_and_zero_padding_do_not_match() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b"abc\0"));
        assert!(!constant_time_eq(b"", b"\0"));
    }

    #[test]
    fn difference_past_the_minimum_scan_is_seen() {
        let mut a = vec![7u8; 600];
        let b = a.clone();
        assert!(constant_time_eq(&a, &b));
        a[599] = 8;
        assert!(!constant_time_eq(&a, &b));
    }
}
