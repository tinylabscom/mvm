//! Order-preserving parallel map over scoped threads.
//!
//! Every parallel workload in the image pipeline — the rootfs walk, the ext4
//! directory/symlink block emission, the dm-verity hash tree, the overlay and
//! initramfs staging copies — is the same shape: map a pure function over an
//! owned collection and keep the results in input order. That is a fraction of
//! what a work-stealing scheduler offers, and input order is something these
//! callers actively need (`rootfs` re-sorted rayon's output by guest path to
//! recover determinism).
//!
//! `std::thread::scope` covers it in a few lines and borrows from the caller's
//! frame, so nothing here needs `'static` or an `Arc`.

/// Map `f` over `items` in parallel, returning results in **input order**.
///
/// Work is split into one contiguous chunk per worker rather than a shared
/// queue: the callers all have uniform per-item cost (one block hash, one
/// directory's blocks, one file copy), so static chunking gets the same
/// throughput without a scheduler.
///
/// Runs inline on the calling thread when there is one worker or one chunk of
/// work, which keeps small inputs free of thread-spawn overhead and keeps the
/// single-threaded path easy to reason about in tests.
pub fn par_map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let workers = worker_count(items.len());
    if workers <= 1 {
        return items.into_iter().map(f).collect();
    }

    // Ceil-divide so `workers` chunks cover the input; the last chunk may be
    // short. `chunk_len >= 1` because `workers <= items.len()` here.
    let chunk_len = items.len().div_ceil(workers);
    // Slots let a worker move its `T` out of the shared buffer without
    // requiring `T: Clone` or `T: Default`.
    let mut slots: Vec<Option<T>> = items.into_iter().map(Some).collect();
    let f = &f;
    let mut out: Vec<Vec<R>> = std::thread::scope(|scope| {
        let handles: Vec<_> = slots
            .chunks_mut(chunk_len)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter_mut()
                        .map(|slot| f(slot.take().expect("each slot is taken exactly once")))
                        .collect::<Vec<R>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
            })
            .collect()
    });

    let mut flat = Vec::with_capacity(out.iter().map(Vec::len).sum());
    for chunk in &mut out {
        flat.append(chunk);
    }
    flat
}

/// Number of workers to split `len` items across: never more workers than
/// items, and never more than the host's available parallelism.
fn worker_count(len: usize) -> usize {
    if len <= 1 {
        return 1;
    }
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    cpus.min(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_input_order() {
        let out = par_map((0..1000usize).collect(), |i| i * 2);
        assert_eq!(out, (0..1000usize).map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn handles_empty_and_single_inputs() {
        assert_eq!(par_map(Vec::<u8>::new(), |x| x), Vec::<u8>::new());
        assert_eq!(par_map(vec![7u8], |x| x + 1), vec![8u8]);
    }

    #[test]
    fn input_not_evenly_divisible_by_worker_count_keeps_every_item() {
        // A ragged last chunk is the case a chunk-length off-by-one would drop.
        for len in 1..=97usize {
            let out = par_map((0..len).collect(), |i| i);
            assert_eq!(out, (0..len).collect::<Vec<_>>(), "len={len}");
        }
    }

    #[test]
    fn moves_non_clone_values_through() {
        // `String` is neither `Copy` nor `Default`-cheap; assert the take-based
        // move path hands the original allocation to `f`.
        let items: Vec<String> = (0..64).map(|i| format!("item-{i}")).collect();
        let out = par_map(items, |s| s.len());
        assert_eq!(out.len(), 64);
        assert_eq!(out[0], "item-0".len());
    }

    #[test]
    fn collects_into_result_short_circuiting_at_the_call_site() {
        // The `Result` callers keep rayon's shape: map to `Result`, collect.
        let ok: Result<Vec<usize>, String> =
            par_map((0..50usize).collect(), Ok).into_iter().collect();
        assert_eq!(ok.unwrap().len(), 50);

        let err: Result<Vec<usize>, String> = par_map((0..50usize).collect(), |i| {
            if i == 17 {
                Err("boom".to_string())
            } else {
                Ok(i)
            }
        })
        .into_iter()
        .collect();
        assert_eq!(err.unwrap_err(), "boom");
    }

    #[test]
    fn propagates_a_worker_panic_to_the_caller() {
        let result = std::panic::catch_unwind(|| {
            par_map((0..256usize).collect(), |i| {
                assert_ne!(i, 200, "worker panic");
                i
            })
        });
        assert!(result.is_err(), "a panicking worker must not be swallowed");
    }
}
