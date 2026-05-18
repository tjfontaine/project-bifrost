// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// DTrace aggregation kinds and planner helpers.
//
// An aggregation in D source looks like `@x[key] = count()` /
// `@y[key] = quantize(value)`. libdtrace compiles each `@var[…]`
// reference into an action chain that carries:
//
//   1. A DIFEXPR action computing the key tuple.
//   2. An AggSentinel action whose `dofa_arg` carries the agg variable
//      id and whose kind discriminator (low byte of `dofa_kind` above
//      `DTRACEAGG_BASE = 0x100`) is the aggregation operator.
//
// This module names the operators, classifies their key/value shape,
// and gives the host a small "agg plan" type used by the
// capability-fanout planner.

use crate::LowerError;

pub const DTRACEAGG_BASE: u32 = 0x0100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AggKind {
    /// `count()` — increment a u64.
    Count = 0x0101,
    /// `min()` — track minimum signed i64.
    Min = 0x0102,
    /// `max()` — track maximum signed i64.
    Max = 0x0103,
    /// `avg()` — running sum + count, host divides on render.
    Avg = 0x0104,
    /// `sum()` — running signed sum.
    Sum = 0x0105,
    /// `stddev()` — running (n, sum, sum-of-squares).
    StdDev = 0x0106,
    /// `quantize(v)` — power-of-two bucketed histogram.
    Quantize = 0x0107,
    /// `lquantize(v, base, top, step)` — linear bucketed histogram.
    LQuantize = 0x0108,
    /// `llquantize(v, factor, low, high, steps)` — log-linear histogram.
    LLQuantize = 0x0109,
}

impl AggKind {
    pub fn from_u32(v: u32) -> Result<Self, LowerError> {
        Ok(match v {
            0x0101 => Self::Count,
            0x0102 => Self::Min,
            0x0103 => Self::Max,
            0x0104 => Self::Avg,
            0x0105 => Self::Sum,
            0x0106 => Self::StdDev,
            0x0107 => Self::Quantize,
            0x0108 => Self::LQuantize,
            0x0109 => Self::LLQuantize,
            _ => return Err(LowerError::UnknownAggKind(v)),
        })
    }

    /// Bytes per bucket array for histogram kinds. `0` for scalar aggs.
    /// Buckets live alongside the agg row in SHMEM; the renderer
    /// knows how to interpret them. Numbers are the canonical libdtrace
    /// defaults — adapters that want a custom bucket count carry the
    /// override in their AggParams alongside the kind.
    pub const fn default_bucket_count(self) -> u32 {
        match self {
            Self::Count
            | Self::Min
            | Self::Max
            | Self::Avg
            | Self::Sum
            | Self::StdDev => 0,
            // `quantize` is signed-log2 across [-2^63, 2^63), bucket
            // count = 2*64 + 1 = 129. libdtrace agrees.
            Self::Quantize => 129,
            // `lquantize` carries (base, top, step) — bucket count is
            // determined per-call from those parameters. Default
            // placeholder; planner overwrites.
            Self::LQuantize => 0,
            Self::LLQuantize => 0,
        }
    }

    /// True for histogram-shaped aggs that need a per-bucket payload.
    pub const fn is_histogram(self) -> bool {
        matches!(self, Self::Quantize | Self::LQuantize | Self::LLQuantize)
    }
}

/// Compact plan record for one aggregation: identity, kind, and the
/// per-bucket footprint the renderer will need. The host capability
/// planner aggregates these across all per-target ECB-walk results so
/// it can pre-size its merge buffer.
#[derive(Debug, Clone, Copy)]
pub struct AggPlan {
    /// DTrace agg variable id (`@var` slot, allocated by libdtrace).
    pub var_id: u32,
    /// Section index of the DIFO that computes the key.
    pub key_difo: u32,
    /// Section index of the DIFO that computes the value (or 0 for
    /// `count()` which takes no value expression).
    pub value_difo: u32,
    pub kind: AggKind,
    /// Number of buckets (histogram kinds) — 0 for scalars.
    pub bucket_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_is_scalar() {
        let k = AggKind::Count;
        assert!(!k.is_histogram());
        assert_eq!(k.default_bucket_count(), 0);
    }

    #[test]
    fn quantize_is_histogram() {
        let k = AggKind::Quantize;
        assert!(k.is_histogram());
        assert_eq!(k.default_bucket_count(), 129);
    }

    #[test]
    fn unknown_kind_surfaces() {
        match AggKind::from_u32(0x9999) {
            Err(LowerError::UnknownAggKind(0x9999)) => {}
            other => panic!("expected UnknownAggKind, got {:?}", other),
        }
    }
}
