//! Shannon-entropy / packing heuristic.
//!
//! Entropy alone is a high-false-positive signal, so the caller MUST gate it by
//! file type (archives/media are exempt) and treat the result as a *score*, not
//! a verdict. Thresholds (empirically derived; see plan research):
//!   >= 7.2  suspicious   |   >= 7.5  high-confidence   |   ~8.0  packed/encrypted.

/// Compute Shannon entropy of `data` over its byte histogram. Range `0.0..=8.0`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub const SUSPICIOUS: f64 = 7.2;
pub const HIGH: f64 = 7.5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn uniform_bytes_approach_eight() {
        let data: Vec<u8> = (0..=255u16).cycle().take(65536).map(|b| b as u8).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.99, "expected ~8.0, got {h}");
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }
}
