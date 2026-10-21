//! Decoding must not reserve memory far beyond the size of its input.
//!
//! This is an integration test so its counting global allocator only applies
//! to this test binary.

use common_access_token::Token;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A COSE structure whose unprotected header is `{1: X}`, where X is a chain
/// of 31 nested arrays (the maximum depth). Each array declares as many items
/// as the remaining input could hold, with the next array as its first item,
/// followed by `pad` one-byte items.
fn nested_array_chain(pad: u32) -> Vec<u8> {
    let mut bytes = vec![0x84, 0x43, 0xa1, 0x01, 0x05, 0xa1, 0x01];
    for level in 0..31u32 {
        bytes.push(0x9a);
        bytes.extend_from_slice(&(pad + (30 - level) * 5).to_be_bytes());
    }
    bytes.resize(bytes.len() + pad as usize, 0x00);
    bytes
}

#[test]
fn test_nested_declared_lengths_do_not_multiply_allocation() {
    let input = nested_array_chain(100_000);

    let baseline = CURRENT.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    let result = Token::from_bytes(&input);
    let peak = PEAK.load(Ordering::SeqCst) - baseline;

    assert!(result.is_err());
    // Decoding the innermost array legitimately holds one value per input
    // byte (tens of bytes each); preallocating every level's declared length
    // reached roughly 1000x the input.
    assert!(
        peak < 64 * input.len(),
        "decoding a {}-byte input reserved {peak} bytes ({}x)",
        input.len(),
        peak / input.len()
    );
}
