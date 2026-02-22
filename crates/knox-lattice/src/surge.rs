pub const SURGE_PHI: f64 = 1.618_034;
pub const SURGE_DURATION_MS: u64 = 58_683_400; // 16h 18m 03.4s
pub const SURGE_BLOCK_CAP: u64 = 16_180;
pub const SURGE_WARNING_MS: u64 = 10 * 60 * 1000; // 10 minutes
pub const SURGE_COOLDOWN_MS: u64 = 9_708_000; // 161.8 minutes

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurgePhase {
    Normal,
    Warning {
        starts_in_ms: u64,
    },
    Active {
        block_index: u64,
        remaining_blocks: u64,
        ends_in_ms: u64,
    },
    Cooldown {
        ends_in_ms: u64,
    },
}

pub fn month_bounds_utc_ms(timestamp_ms: u64) -> (u64, u64) {
    let days = (timestamp_ms / 1000 / 86_400) as i64;
    let (year, month, _) = civil_from_days(days);
    let start_days = days_from_civil(year, month, 1);
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let end_days = days_from_civil(next_year, next_month, 1);
    (
        (start_days as u64).saturating_mul(86_400_000),
        (end_days as u64).saturating_mul(86_400_000),
    )
}

pub fn surge_start_ms(
    first_block_timestamp_ms: u64,
    first_block_hash: [u8; 32],
    month_duration_ms: u64,
) -> u64 {
    let (month_start, _) = month_bounds_utc_ms(first_block_timestamp_ms);
    let mut h = blake3::Hasher::new();
    h.update(b"knox-lattice-surge-window-v3");
    h.update(&month_start.to_le_bytes());
    h.update(&month_duration_ms.to_le_bytes());
    h.update(&first_block_hash);
    let digest = h.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    let seed = u64::from_le_bytes(head);
    let window = month_duration_ms.saturating_sub(SURGE_DURATION_MS);
    let offset = if window == 0 { 0 } else { seed % window };
    month_start.saturating_add(offset)
}

pub fn surge_phase(
    now_ms: u64,
    first_block_timestamp_ms: u64,
    first_block_hash: [u8; 32],
    month_duration_ms: u64,
    prior_surge_blocks: u64,
    cap_reached_timestamp_ms: Option<u64>,
) -> SurgePhase {
    let start_ms = surge_start_ms(
        first_block_timestamp_ms,
        first_block_hash,
        month_duration_ms,
    );
    let time_end_ms = start_ms.saturating_add(SURGE_DURATION_MS);

    if now_ms < start_ms {
        let wait = start_ms.saturating_sub(now_ms);
        if wait <= SURGE_WARNING_MS {
            return SurgePhase::Warning { starts_in_ms: wait };
        }
        return SurgePhase::Normal;
    }

    if let Some(cap_ts) = cap_reached_timestamp_ms {
        let cooldown_end = cap_ts.saturating_add(SURGE_COOLDOWN_MS);
        if now_ms < cap_ts {
            let next_idx = prior_surge_blocks.saturating_add(1);
            let remaining = SURGE_BLOCK_CAP.saturating_sub(prior_surge_blocks);
            return SurgePhase::Active {
                block_index: next_idx,
                remaining_blocks: remaining,
                ends_in_ms: cap_ts.saturating_sub(now_ms),
            };
        }
        if now_ms < cooldown_end {
            return SurgePhase::Cooldown {
                ends_in_ms: cooldown_end.saturating_sub(now_ms),
            };
        }
        return SurgePhase::Normal;
    }

    if now_ms < time_end_ms {
        let next_idx = prior_surge_blocks.saturating_add(1).min(SURGE_BLOCK_CAP);
        let remaining = SURGE_BLOCK_CAP.saturating_sub(prior_surge_blocks);
        return SurgePhase::Active {
            block_index: next_idx,
            remaining_blocks: remaining,
            ends_in_ms: time_end_ms.saturating_sub(now_ms),
        };
    }

    let cooldown_end = time_end_ms.saturating_add(SURGE_COOLDOWN_MS);
    if now_ms < cooldown_end {
        return SurgePhase::Cooldown {
            ends_in_ms: cooldown_end.saturating_sub(now_ms),
        };
    }
    SurgePhase::Normal
}

pub fn surge_difficulty_bits(base_bits: u32, surge_block_index: u64) -> u32 {
    if surge_block_index == 0 {
        return base_bits;
    }
    let factor = (surge_block_index as f64 / 1000.0) * SURGE_PHI.log2();
    base_bits.saturating_add(factor.round() as u32)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_bounds_feb_2026() {
        // 2026-02-17T00:00:00Z
        let ts = 1_771_286_400_000u64;
        let (start, end) = month_bounds_utc_ms(ts);
        assert_eq!(start, 1_769_904_000_000u64); // 2026-02-01
        assert_eq!(end, 1_772_323_200_000u64); // 2026-03-01
    }

    #[test]
    fn surge_phase_transitions() {
        let month_ms = 31 * 86_400_000u64;
        let first_ts = 1_700_000_000_000u64;
        let hash = [7u8; 32];
        let start = surge_start_ms(first_ts, hash, month_ms);

        let phase = surge_phase(
            start.saturating_sub(60_000),
            first_ts,
            hash,
            month_ms,
            0,
            None,
        );
        assert!(matches!(phase, SurgePhase::Warning { .. }));

        let phase = surge_phase(
            start.saturating_add(1_000),
            first_ts,
            hash,
            month_ms,
            4,
            None,
        );
        assert!(matches!(phase, SurgePhase::Active { block_index: 5, .. }));

        let cap_ts = start.saturating_add(10_000);
        let phase = surge_phase(
            cap_ts.saturating_add(1_000),
            first_ts,
            hash,
            month_ms,
            SURGE_BLOCK_CAP,
            Some(cap_ts),
        );
        assert!(matches!(phase, SurgePhase::Cooldown { .. }));
    }

    #[test]
    fn surge_difficulty_moves_up() {
        let base = 12u32;
        let d1 = surge_difficulty_bits(base, 1);
        let d1000 = surge_difficulty_bits(base, 1_000);
        let d16180 = surge_difficulty_bits(base, 16_180);
        assert_eq!(d1, base);
        assert!(d1000 >= base + 1);
        assert!(d16180 > d1000);
    }
}
