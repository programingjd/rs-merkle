use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

struct TrackingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TRACK: AtomicBool = AtomicBool::new(false);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    if TRACK.load(Relaxed) {
        PEAK.fetch_max(live, Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A realloc may need both old and new buffers at once. Count that upper
        // bound so a large realloc cannot pass as a tiny net size increase.
        if TRACK.load(Relaxed) {
            PEAK.fetch_max(LIVE.load(Relaxed).saturating_add(new_size), Relaxed);
        }
        let result = unsafe { System.realloc(ptr, layout, new_size) };
        if !result.is_null() {
            if new_size >= layout.size() {
                allocated(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn start_tracking() -> usize {
    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    TRACK.store(true, Relaxed);
    baseline
}

fn stop_tracking(baseline: usize) -> usize {
    TRACK.store(false, Relaxed);
    PEAK.load(Relaxed).saturating_sub(baseline)
}

#[test]
fn building_without_history_and_appending_one_leaf_have_bounded_allocations() {
    let count = (1usize << 15) - 1;
    let baseline = start_tracking();
    let mut tree = MerkleTree::<Sha256, false>::from_leaves_iter(
        (0..count).map(|i| Sha256::hash(&i.to_le_bytes())),
    );
    let build_peak = stop_tracking(baseline);
    // One set of indexed nodes, plus a small allowance for the test harness.
    let tree_bytes = 2 * (count + 1) * std::mem::size_of::<(usize, [u8; 32])>();
    assert!(
        build_peak < tree_bytes + 128 * 1024,
        "build peak: {}",
        build_peak
    );

    let old_root = tree.root();
    let baseline = start_tracking();
    tree.insert(Sha256::hash(b"last leaf")).commit();
    let commit_peak = stop_tracking(baseline);
    assert!(
        commit_peak < 128 * 1024,
        "one-leaf commit peak: {}",
        commit_peak
    );
    assert_eq!(tree.leaves_len(), count + 1);
    assert_ne!(tree.root(), old_root);
}
