// SPDX-License-Identifier: Apache-2.0
//! Multi-target N-ring merged renderer.
//!
//! Per [`plan::Plan`], a Bifrost session may drive multiple guest
//! targets concurrently — Linux smolvm + FreeBSD QEMU is the
//! motivating shape.  Each target publishes records into its own
//! per-VM data SHM ring.  The host wants one ordered, target-tagged
//! record stream so a single `printf` / `printa` can render both
//! kernels' contributions interleaved on host wall-clock time.
//!
//! This module is the cross-target merge layer.  It is deliberately
//! schema-blind: callers hand it `(target_id, gns, source_seq,
//! payload)` tuples and it returns merged records in the contract
//! described below.  Schema decoding stays in the per-target
//! `GuestRecordSchema` path so the merger never learns Linux BFR7 or
//! native-DTrace DOF record shapes.
//!
//! ## Ordering contract
//!
//! Two invariants the merger preserves:
//!
//! 1. **Per-target producer order.**  Records from one source emerge
//!    in the same order they arrived (matching the per-CPU ring
//!    contract today).  We use the caller-supplied `source_seq` to
//!    break ties when two records share a `gns`; we never reorder
//!    records within one source.
//!
//! 2. **Cross-target host-wall-clock order with bounded jitter.**
//!    Records across sources are released in `gns`-ascending order,
//!    but only once `gns + lookback_ns <= now_ns`.  The lookback
//!    window (default 50 ms) lets us absorb the inevitable scheduling
//!    skew between two VMs writing into independent rings — without
//!    it, a late record from target A could land in the merged output
//!    after we've already emitted a later record from target B.
//!
//! The renderer's end-of-session reconciliation calls [`drain_all`]
//! to flush every buffered record regardless of lookback; that's how
//! we make `printa` over a cross-target aggregation deterministic.

use std::collections::VecDeque;

/// One record after merge: every payload is stamped with the
/// `target_id` the planner assigned to the originating guest.  The
/// `gns` and `source_seq` fields are kept on the record so downstream
/// renderers (and tests) can reason about ordering without re-reading
/// the on-wire header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedRecord {
    pub target_id: String,
    pub gns: u64,
    pub source_seq: u64,
    pub payload: Vec<u8>,
}

/// Configurable lookback the merge layer uses to absorb cross-VM
/// scheduling jitter when ordering by `gns`.
pub const DEFAULT_LOOKBACK_NS: u64 = 50_000_000; // 50 ms

/// N-ring merger.  Built once per session against the plan's target
/// list; one `SourceState` per target keeps that target's pending
/// records in producer order, and `drain_eligible` emits the records
/// whose host-wall-clock time has fallen outside the lookback
/// window.
pub struct MergedRing {
    sources: Vec<SourceState>,
    lookback_ns: u64,
}

struct SourceState {
    target_id: String,
    /// Pending records in producer order (gns and source_seq are both
    /// expected to be monotonic per source, but we tolerate equal
    /// values for the per-CPU multi-producer case by sorting on
    /// (gns, source_seq) at drain time rather than insertion time).
    queue: VecDeque<TaggedRecord>,
}

impl MergedRing {
    pub fn new<I, S>(target_ids: I, lookback_ns: u64) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sources: target_ids
                .into_iter()
                .map(|id| SourceState {
                    target_id: id.into(),
                    queue: VecDeque::new(),
                })
                .collect(),
            lookback_ns,
        }
    }

    pub fn with_default_lookback<I, S>(target_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new(target_ids, DEFAULT_LOOKBACK_NS)
    }

    pub fn target_ids(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(|s| s.target_id.as_str())
    }

    /// Push one record onto target `source_idx`'s queue.  Stamps the
    /// target_id from the source slot — callers must not pre-stamp.
    /// Panics if `source_idx` is out of range; that's a planner bug
    /// (the orchestrator and the merger share a fixed source list).
    pub fn push(&mut self, source_idx: usize, gns: u64, source_seq: u64, payload: Vec<u8>) {
        let src = &mut self.sources[source_idx];
        src.queue.push_back(TaggedRecord {
            target_id: src.target_id.clone(),
            gns,
            source_seq,
            payload,
        });
    }

    /// Push one record by target id rather than index.  Returns false
    /// if the id isn't in the plan (caller should treat as a
    /// configuration error and surface it; we don't silently drop).
    pub fn push_by_id(&mut self, target_id: &str, gns: u64, source_seq: u64, payload: Vec<u8>) -> bool {
        let Some(idx) = self.sources.iter().position(|s| s.target_id == target_id) else {
            return false;
        };
        self.push(idx, gns, source_seq, payload);
        true
    }

    /// Emit every record whose `gns + lookback_ns <= now_ns`, in
    /// `gns`-ascending order, breaking ties on `(target_id,
    /// source_seq)` so the order is stable across runs.
    ///
    /// Per the invariant: we never advance past a record at the head
    /// of one queue whose `gns` is still inside the lookback window —
    /// even if a later record on a different queue is already
    /// eligible — because doing so would let us emit a later
    /// timestamp before an earlier one.  The next call (with a later
    /// `now_ns`) will release them in order.
    pub fn drain_eligible(&mut self, now_ns: u64) -> Vec<TaggedRecord> {
        let cutoff = now_ns.saturating_sub(self.lookback_ns);
        let mut out = Vec::new();
        loop {
            // Pick the source whose head has the smallest gns, ties
            // broken by target_id then source_seq (deterministic).
            let mut best: Option<usize> = None;
            for (i, src) in self.sources.iter().enumerate() {
                let Some(head) = src.queue.front() else {
                    continue;
                };
                match best {
                    None => best = Some(i),
                    Some(b) => {
                        let bhead = self.sources[b].queue.front().unwrap();
                        if (head.gns, &head.target_id, head.source_seq)
                            < (bhead.gns, &bhead.target_id, bhead.source_seq)
                        {
                            best = Some(i);
                        }
                    }
                }
            }
            let Some(i) = best else {
                break;
            };
            let head_gns = self.sources[i].queue.front().unwrap().gns;
            if head_gns > cutoff {
                break;
            }
            out.push(self.sources[i].queue.pop_front().unwrap());
        }
        out
    }

    /// Flush every buffered record in (gns, target_id, source_seq)
    /// order.  Called at session END to reconcile the cross-target
    /// aggregations and to make the final printa() output
    /// deterministic.
    pub fn drain_all(&mut self) -> Vec<TaggedRecord> {
        let mut all = Vec::new();
        for src in self.sources.iter_mut() {
            all.extend(src.queue.drain(..));
        }
        all.sort_by(|a, b| {
            a.gns
                .cmp(&b.gns)
                .then_with(|| a.target_id.cmp(&b.target_id))
                .then_with(|| a.source_seq.cmp(&b.source_seq))
        });
        all
    }

    /// How many records are buffered across all sources.  Used by the
    /// orchestrator's shutdown loop to bound the drain wait.
    pub fn pending(&self) -> usize {
        self.sources.iter().map(|s| s.queue.len()).sum()
    }
}

/// Cross-target aggregation reducer.  When a D
/// source like
///
/// ```text
/// tracepoint:guest:net:netif_receive_skb { @rx["linux"]   = count(); }
/// fbt:kernel:tcp_input:entry           { @rx["freebsd"] = count(); }
/// ```
///
/// runs across two kernels, each guest emits its own `@rx` snapshot
/// keyed on its own copy of the key tuple — `linux` from the Linux
/// target, `freebsd` from the FreeBSD target.  The reducer
/// bucket-merges those snapshots into one cross-kernel table the
/// host renderer can hand to `printa`.
///
/// Three shapes per agg:
///   - `count` / `sum`        — additive scalar; sum across targets.
///   - `min` / `max`          — bound; min-/max-fold across targets.
///   - `quantize` / `lquantize` — bucket histogram; per-bucket add
///                                across targets, preserves bucket
///                                base/step.
///
/// The reducer is keyed on `(agg_name, key_tuple)`.  `key_tuple` is
/// the user-supplied D-side key (`"linux"`, `(123u32, "tcp")`, …);
/// the `target_id` is **not** part of the reducer key — that's the
/// whole point of the cross-target view.  If two targets happen to
/// emit the same `(@rx, "linux")` row the reducer still folds them
/// together; the inner per-target contribution is tracked separately
/// via [`CrossTargetAggReducer::contributors`] so the renderer can
/// show provenance when it matters.
pub struct CrossTargetAggReducer {
    rows: std::collections::BTreeMap<(String, String), CrossTargetAggCell>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossTargetAggValue {
    Scalar(i64),
    Histogram(Vec<(i64, u64)>),
}

#[derive(Clone, Debug)]
pub struct CrossTargetAggCell {
    pub kind: CrossTargetAggKind,
    pub value: CrossTargetAggValue,
    /// Per-target contribution to this row.  Lets renderers show
    /// "linux contributed 42, freebsd contributed 17" alongside the
    /// summed total when the demo asks for it.
    pub contributors: std::collections::BTreeMap<String, CrossTargetAggValue>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossTargetAggKind {
    Count,
    Sum,
    Min,
    Max,
    Quantize,
    Lquantize,
}

impl Default for CrossTargetAggReducer {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossTargetAggReducer {
    pub fn new() -> Self {
        Self {
            rows: std::collections::BTreeMap::new(),
        }
    }

    /// Fold one per-target contribution into the cross-target row.
    /// `target_id` is recorded against `contributors`; the row's own
    /// `value` accumulates across every target.
    pub fn merge(
        &mut self,
        target_id: &str,
        agg_name: &str,
        key_tuple: &str,
        kind: CrossTargetAggKind,
        value: CrossTargetAggValue,
    ) {
        use std::collections::btree_map::Entry;
        let cell = self
            .rows
            .entry((agg_name.to_string(), key_tuple.to_string()))
            .or_insert_with(|| CrossTargetAggCell {
                kind,
                value: empty_value(kind),
                contributors: Default::default(),
            });
        if cell.kind != kind {
            // Shape conflict between targets (e.g. one says count,
            // the other says quantize). Histograms strictly dominate
            // scalars: if either side ships a quantize bucket array
            // for `@<name>`, the user wrote `quantize()` in the D
            // source, so the histogram form is what they asked for.
            // Promote the cell so the FreeBSD-side histogram doesn't
            // get hidden behind a Linux-side scalar that lowered to
            // count() because the BPF backend didn't recognize the
            // shape.  Per-target contributors keep the raw shapes.
            let incoming_is_hist = matches!(
                kind,
                CrossTargetAggKind::Quantize | CrossTargetAggKind::Lquantize,
            );
            let cell_is_hist = matches!(
                cell.kind,
                CrossTargetAggKind::Quantize | CrossTargetAggKind::Lquantize,
            );
            if incoming_is_hist && !cell_is_hist {
                cell.kind = kind;
                cell.value = value.clone();
            }
            cell.contributors
                .insert(target_id.to_string(), value);
            return;
        }
        match (kind, &mut cell.value, &value) {
            (
                CrossTargetAggKind::Count | CrossTargetAggKind::Sum,
                CrossTargetAggValue::Scalar(acc),
                CrossTargetAggValue::Scalar(v),
            ) => {
                *acc += v;
            }
            (
                CrossTargetAggKind::Min,
                CrossTargetAggValue::Scalar(acc),
                CrossTargetAggValue::Scalar(v),
            ) => {
                *acc = (*acc).min(*v);
            }
            (
                CrossTargetAggKind::Max,
                CrossTargetAggValue::Scalar(acc),
                CrossTargetAggValue::Scalar(v),
            ) => {
                *acc = (*acc).max(*v);
            }
            (
                CrossTargetAggKind::Quantize | CrossTargetAggKind::Lquantize,
                CrossTargetAggValue::Histogram(acc),
                CrossTargetAggValue::Histogram(v),
            ) => {
                // Per-bucket additive merge. Keep buckets sorted so
                // the renderer can walk them in canonical order.
                let mut merged: std::collections::BTreeMap<i64, u64> =
                    acc.drain(..).collect();
                for (bucket, count) in v {
                    *merged.entry(*bucket).or_insert(0) += *count;
                }
                *acc = merged.into_iter().collect();
            }
            _ => {
                // Type/shape mismatch within the same kind (e.g. a
                // scalar fold with a histogram value). Surface via
                // contributors and leave the row untouched.
            }
        }
        match cell.contributors.entry(target_id.to_string()) {
            Entry::Vacant(slot) => {
                slot.insert(value);
            }
            Entry::Occupied(mut slot) => {
                // Within one target, multiple AGG_SNAPSHOTs over the
                // session naturally arrive cumulatively; the last
                // snapshot is the most-recent total. Overwrite.
                slot.insert(value);
            }
        }
    }

    pub fn rows(&self) -> impl Iterator<Item = (&str, &str, &CrossTargetAggCell)> {
        self.rows
            .iter()
            .map(|((name, key), cell)| (name.as_str(), key.as_str(), cell))
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render every cross-target row to stdout in a stable order.
    /// Each line is `agg <name> key <key> value <value>` — terse so
    /// the killer-demo printa output is the focus.
    pub fn dump(&self) {
        for (name, key, cell) in self.rows() {
            match &cell.value {
                CrossTargetAggValue::Scalar(v) => {
                    println!("xagg @{name}[{key}] = {v}");
                }
                CrossTargetAggValue::Histogram(buckets) => {
                    let parts: Vec<String> = buckets
                        .iter()
                        .map(|(b, c)| format!("{b}:{c}"))
                        .collect();
                    println!("xagg @{name}[{key}] = quantize {{ {} }}", parts.join(", "));
                }
            }
        }
    }
}

fn empty_value(kind: CrossTargetAggKind) -> CrossTargetAggValue {
    match kind {
        CrossTargetAggKind::Count | CrossTargetAggKind::Sum => CrossTargetAggValue::Scalar(0),
        CrossTargetAggKind::Min => CrossTargetAggValue::Scalar(i64::MAX),
        CrossTargetAggKind::Max => CrossTargetAggValue::Scalar(i64::MIN),
        CrossTargetAggKind::Quantize | CrossTargetAggKind::Lquantize => {
            CrossTargetAggValue::Histogram(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_target_id_from_source_slot() {
        let mut m = MergedRing::with_default_lookback(["linux", "freebsd"]);
        m.push(0, 1_000, 0, b"linux-rec".to_vec());
        m.push(1, 1_000, 0, b"freebsd-rec".to_vec());
        let out = m.drain_all();
        let by_id: std::collections::HashMap<&str, &[u8]> = out
            .iter()
            .map(|r| (r.target_id.as_str(), r.payload.as_slice()))
            .collect();
        assert_eq!(by_id.get("linux"), Some(&b"linux-rec".as_slice()));
        assert_eq!(by_id.get("freebsd"), Some(&b"freebsd-rec".as_slice()));
    }

    #[test]
    fn push_by_id_resolves_or_reports() {
        let mut m = MergedRing::with_default_lookback(["linux", "freebsd"]);
        assert!(m.push_by_id("freebsd", 1, 0, vec![]));
        assert!(!m.push_by_id("illumos", 1, 0, vec![]));
        assert_eq!(m.pending(), 1);
    }

    #[test]
    fn drain_eligible_respects_lookback() {
        // Lookback = 100ns. Records at gns=50 and gns=200; now=210.
        // Cutoff = 210 - 100 = 110.  Record at gns=50 is eligible,
        // gns=200 is still inside the lookback window.
        let mut m = MergedRing::new(["a", "b"], 100);
        m.push(0, 50, 0, b"early".to_vec());
        m.push(1, 200, 0, b"late".to_vec());
        let out = m.drain_eligible(210);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"early");
        assert_eq!(m.pending(), 1);

        // Now extend past gns=200's lookback (200 + 100 = 300).
        let out2 = m.drain_eligible(300);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].payload, b"late");
        assert_eq!(m.pending(), 0);
    }

    #[test]
    fn drain_eligible_interleaves_by_gns_across_sources() {
        // Two streams with interleaved timestamps. The merger must
        // emit globally in gns order, not append source-by-source.
        let mut m = MergedRing::new(["linux", "freebsd"], 0);
        m.push(0, 10, 0, b"L0".to_vec());
        m.push(0, 30, 1, b"L1".to_vec());
        m.push(0, 50, 2, b"L2".to_vec());
        m.push(1, 20, 0, b"F0".to_vec());
        m.push(1, 40, 1, b"F1".to_vec());
        let out = m.drain_eligible(100);
        let labels: Vec<&[u8]> = out.iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(
            labels,
            vec![
                b"L0".as_slice(),
                b"F0".as_slice(),
                b"L1".as_slice(),
                b"F1".as_slice(),
                b"L2".as_slice(),
            ]
        );
    }

    #[test]
    fn drain_eligible_blocks_on_in_window_head_even_if_other_source_is_old() {
        // Crux of the lookback invariant: linux has a record at
        // gns=200 (still in lookback at now=210, cutoff=110); freebsd
        // has gns=50 (old).  We can emit freebsd's old record, but
        // we must NOT emit any linux record yet.  After lookback
        // expires we emit linux's.
        //
        // Then: a new freebsd record at gns=80 arrives.  It's older
        // than the cutoff, but the linux head is still in window —
        // we should still emit freebsd@80 because the linux head
        // (gns=200) is later than freebsd@80 and emitting freebsd@80
        // can't violate global order.
        let mut m = MergedRing::new(["linux", "freebsd"], 100);
        m.push(0, 200, 0, b"L-late".to_vec());
        m.push(1, 50, 0, b"F-old".to_vec());
        let out = m.drain_eligible(210);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"F-old");

        m.push(1, 80, 1, b"F-old-2".to_vec());
        let out2 = m.drain_eligible(210);
        // F-old-2 still emits (gns=80 < cutoff=110, and linux head
        // is gns=200 > 80, so no global-order risk).
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].payload, b"F-old-2");

        // Push lookback past linux's record.
        let out3 = m.drain_eligible(400);
        assert_eq!(out3.len(), 1);
        assert_eq!(out3[0].payload, b"L-late");
    }

    #[test]
    fn drain_all_orders_globally_at_end_of_session() {
        let mut m = MergedRing::new(["linux", "freebsd"], 1_000_000);
        m.push(0, 100, 0, b"L0".to_vec());
        m.push(1, 50, 0, b"F0".to_vec());
        m.push(0, 200, 1, b"L1".to_vec());
        m.push(1, 150, 1, b"F1".to_vec());
        let out = m.drain_all();
        let labels: Vec<&[u8]> = out.iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(
            labels,
            vec![
                b"F0".as_slice(),
                b"L0".as_slice(),
                b"F1".as_slice(),
                b"L1".as_slice(),
            ]
        );
        assert_eq!(m.pending(), 0);
    }

    #[test]
    fn per_target_producer_order_preserved_under_equal_gns() {
        // Two records on the same target with the same gns: the
        // source_seq must break the tie in producer order.
        let mut m = MergedRing::new(["only"], 0);
        m.push(0, 100, 0, b"first".to_vec());
        m.push(0, 100, 1, b"second".to_vec());
        let out = m.drain_eligible(200);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload, b"first");
        assert_eq!(out[1].payload, b"second");
    }

    #[test]
    fn tie_break_across_targets_is_stable_and_deterministic() {
        // Both sources have a record at exactly the same gns. The
        // tie is broken alphabetically on target_id to give a
        // reproducible cross-run ordering; tests downstream rely on
        // this.
        let mut m = MergedRing::new(["zebra", "alpha"], 0);
        m.push(0, 100, 0, b"Z".to_vec()); // zebra
        m.push(1, 100, 0, b"A".to_vec()); // alpha
        let out = m.drain_eligible(200);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].target_id, "alpha");
        assert_eq!(out[1].target_id, "zebra");
    }

    #[test]
    fn pending_counts_across_all_sources() {
        let mut m = MergedRing::with_default_lookback(["a", "b"]);
        assert_eq!(m.pending(), 0);
        m.push(0, 1, 0, vec![]);
        m.push(1, 2, 0, vec![]);
        m.push(1, 3, 1, vec![]);
        assert_eq!(m.pending(), 3);
    }

    #[test]
    fn cross_target_reducer_sums_count_across_targets() {
        // The canonical killer-demo shape: each target contributes a
        // distinct (name, key) row (one keyed "linux", one keyed
        // "freebsd"). Cross-target reducer should hold both rows
        // intact, with the per-target contributor exactly matching
        // its own value.
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "rx",
            "\"linux\"",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(42),
        );
        r.merge(
            "freebsd",
            "rx",
            "\"freebsd\"",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(17),
        );
        let rows: Vec<_> = r
            .rows()
            .map(|(n, k, c)| (n.to_string(), k.to_string(), c.value.clone()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("rx".into(), "\"freebsd\"".into(), CrossTargetAggValue::Scalar(17)),
                ("rx".into(), "\"linux\"".into(), CrossTargetAggValue::Scalar(42)),
            ]
        );
    }

    #[test]
    fn cross_target_reducer_overlapping_rows_sum() {
        // Both targets emit the same (name, key) row — fold by sum.
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "errors",
            "",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(3),
        );
        r.merge(
            "freebsd",
            "errors",
            "",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(5),
        );
        let cell = r.rows().next().unwrap().2;
        assert_eq!(cell.value, CrossTargetAggValue::Scalar(8));
        assert_eq!(cell.contributors.len(), 2);
    }

    #[test]
    fn cross_target_reducer_quantize_buckets_merge_additively() {
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "latency",
            "",
            CrossTargetAggKind::Quantize,
            CrossTargetAggValue::Histogram(vec![(0, 1), (64, 4), (128, 2)]),
        );
        r.merge(
            "freebsd",
            "latency",
            "",
            CrossTargetAggKind::Quantize,
            CrossTargetAggValue::Histogram(vec![(64, 3), (256, 1)]),
        );
        let cell = r.rows().next().unwrap().2;
        assert_eq!(
            cell.value,
            CrossTargetAggValue::Histogram(vec![(0, 1), (64, 7), (128, 2), (256, 1)])
        );
    }

    #[test]
    fn cross_target_reducer_min_max_fold_correctly() {
        let mut rmin = CrossTargetAggReducer::new();
        rmin.merge(
            "linux",
            "first_seen",
            "",
            CrossTargetAggKind::Min,
            CrossTargetAggValue::Scalar(100),
        );
        rmin.merge(
            "freebsd",
            "first_seen",
            "",
            CrossTargetAggKind::Min,
            CrossTargetAggValue::Scalar(50),
        );
        let cell_min = rmin.rows().next().unwrap().2;
        assert_eq!(cell_min.value, CrossTargetAggValue::Scalar(50));

        let mut rmax = CrossTargetAggReducer::new();
        rmax.merge(
            "linux",
            "last_seen",
            "",
            CrossTargetAggKind::Max,
            CrossTargetAggValue::Scalar(100),
        );
        rmax.merge(
            "freebsd",
            "last_seen",
            "",
            CrossTargetAggKind::Max,
            CrossTargetAggValue::Scalar(200),
        );
        let cell_max = rmax.rows().next().unwrap().2;
        assert_eq!(cell_max.value, CrossTargetAggValue::Scalar(200));
    }

    #[test]
    fn cross_target_reducer_histogram_promotes_over_scalar() {
        // Demo path: target `linux` lowers `@latency = quantize(...)`
        // to a scalar count (because its BPF backend didn't recognize
        // the quantize() shape) and target `fbsd` lands the real
        // histogram via libdtrace.  The reducer must surface the
        // histogram in the merged cell — dropping it back to a
        // scalar would silently hide the FreeBSD contribution from
        // the cross-kernel printa output.
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "latency",
            "",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(7),
        );
        r.merge(
            "fbsd",
            "latency",
            "",
            CrossTargetAggKind::Quantize,
            CrossTargetAggValue::Histogram(vec![(0, 1), (64, 4)]),
        );
        let cell = r.rows().next().unwrap().2;
        assert_eq!(cell.kind, CrossTargetAggKind::Quantize);
        assert_eq!(
            cell.value,
            CrossTargetAggValue::Histogram(vec![(0, 1), (64, 4)])
        );
        // Both contributors still tracked verbatim.
        assert!(matches!(
            cell.contributors.get("linux"),
            Some(CrossTargetAggValue::Scalar(7)),
        ));
        assert!(matches!(
            cell.contributors.get("fbsd"),
            Some(CrossTargetAggValue::Histogram(_)),
        ));
    }

    #[test]
    fn cross_target_reducer_kind_conflict_records_contributor_only() {
        // Non-histogram shape conflicts still keep the first kind's
        // accumulator intact (e.g. one target says count, another
        // says max — neither dominates the other semantically).
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "a",
            "x",
            "",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(7),
        );
        r.merge(
            "b",
            "x",
            "",
            CrossTargetAggKind::Max,
            CrossTargetAggValue::Scalar(13),
        );
        let cell = r.rows().next().unwrap().2;
        assert_eq!(cell.kind, CrossTargetAggKind::Count);
        assert_eq!(cell.value, CrossTargetAggValue::Scalar(7));
        assert!(matches!(
            cell.contributors.get("b"),
            Some(CrossTargetAggValue::Scalar(13)),
        ));
    }
}
