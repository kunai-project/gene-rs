//! Counts heap allocations made by `Engine::scan` on a warm engine.
//!
//! This lives in its own test binary because it installs a counting global
//! allocator, and runs as a single test so no other test allocates
//! concurrently.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    borrow::Cow,
    sync::atomic::{AtomicUsize, Ordering},
};

use gene::{Compiler, Engine, Event, FieldGetter, FieldNameIterator, FieldValue, XPath};

struct CountingAlloc;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged and only
// increments a counter on allocation.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Dummy;

impl<'f> FieldGetter<'f> for Dummy {
    fn get_from_iter(&'f self, _: FieldNameIterator<'_>) -> Option<FieldValue<'f>> {
        None
    }

    fn get_from_path(&'f self, path: &XPath) -> Option<FieldValue<'f>> {
        match path.to_string_lossy().as_ref() {
            ".a" => Some("x".into()),
            _ => None,
        }
    }
}

impl<'e> Event<'e> for Dummy {
    fn id(&self) -> i64 {
        1
    }

    fn source(&self) -> Cow<'_, str> {
        Cow::Borrowed("test")
    }
}

/// Total allocations made by 100 scans of a warm engine.
fn allocations_in_100_scans(rules: &str) -> usize {
    let mut c = Compiler::new();
    c.load_rules_from_str(rules).unwrap();
    let mut e = Engine::try_from(c).unwrap();
    // first scan fills the rules cache
    assert!(e.scan(&Dummy).unwrap().is_default_exclude());

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..100 {
        assert!(e.scan(&Dummy).unwrap().is_default_exclude());
    }
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[test]
fn scan_without_match_does_not_allocate() {
    assert_eq!(
        allocations_in_100_scans(
            r#"
name: r
matches:
    $a: .a == "y"
condition: $a
"#
        ),
        0,
        "plain rule"
    );

    assert_eq!(
        allocations_in_100_scans(
            r#"
name: dep
type: dependency
matches:
    $a: .a == "x"
condition: $a
---
name: r
matches:
    $d: rule(dep)
    $b: .a == "y"
condition: $d and $b
"#
        ),
        0,
        "rule with a dependency"
    );
    assert_eq!(
        allocations_in_100_scans(
            r#"
name: dep
type: dependency
matches:
    $missing: .missing == 'x'
condition: $missing
---
name: r
matches:
    $guard: .a == 'y'
    $dep: rule(dep)
condition: $guard and $dep
"#
        ),
        0,
        "unreached failing dependency"
    );
}
