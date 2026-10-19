// NUC-009 One-directional bound: a hint result tied to its inputs only by
// comparisons that all point the same way.

unconstrained fn sqrt_hint(y: u64) -> u64 {
    let mut r: u64 = 0;
    for i in 0..32 {
        if (i as u64) * (i as u64) <= y {
            r = i as u64;
        }
    }
    r
}

unconstrained fn max_hint(a: u32, b: u32) -> u32 {
    if a > b { a } else { b }
}

unconstrained fn min_hint(a: u32, b: u32) -> u32 {
    if a < b { a } else { b }
}

unconstrained fn third_hint(x: u64) -> u64 {
    x / 3
}

unconstrained fn half_hint(x: u32) -> u32 {
    x / 2
}

// expect: NUC-009
pub fn vuln_1(y: u64) -> u64 {
    // Safety: the root does not overshoot
    let r = unsafe { sqrt_hint(y) };
    assert(r < 4294967296);
    assert(r * r <= y);
    r
}

// expect: NUC-009
pub fn vuln_2(y: u64) -> u64 {
    // Safety: the root does not undershoot
    let r = unsafe { sqrt_hint(y) };
    assert(r < 4294967296);
    assert(y < (r + 1) * (r + 1));
    r
}

// expect: NUC-009
pub fn vuln_3(a: u32, b: u32) -> u32 {
    // Safety: the maximum is not below either input
    let m = unsafe { max_hint(a, b) };
    assert(m >= a);
    assert(m >= b);
    m
}

// expect: NUC-009
pub fn vuln_4(a: u32, b: u32) -> u32 {
    // Safety: the minimum is not above either input
    let m = unsafe { min_hint(a, b) };
    assert(m <= a);
    assert(b >= m);
    m
}

// expect: NUC-009
pub fn vuln_5(x: u64) -> u64 {
    // Safety: 3q does not exceed x
    let q = unsafe { third_hint(x) };
    assert(q < 4294967296);
    assert(3 * q <= x);
    q
}

pub fn safe_1(y: u64) -> u64 {
    // Safety: r * r <= y < (r + 1) * (r + 1) pins the root
    let r = unsafe { sqrt_hint(y) };
    assert(r < 4294967296);
    assert(r * r <= y);
    assert(y < (r + 1) * (r + 1));
    r
}

pub fn safe_2(a: u32, b: u32) -> u32 {
    // Safety: the maximum is one of the inputs and not below either
    let m = unsafe { max_hint(a, b) };
    assert((m == a) | (m == b));
    assert(m >= a);
    assert(m >= b);
    m
}

pub fn safe_3(a: u32, b: u32) -> u32 {
    // Safety: the minimum equals one input and is not above either
    let m = unsafe { min_hint(a, b) };
    assert(m <= a);
    assert(m <= b);
    assert((m - a) * (m - b) == 0);
    m
}

pub fn safe_4(x: u32) -> u32 {
    // Safety: 2h <= x < 2h + 2 pins h
    let h = unsafe { half_hint(x) };
    assert(2 * (h as u64) <= x as u64);
    assert((x as u64) < 2 * (h as u64) + 2);
    h
}

pub fn safe_5(x: u32) -> u32 {
    // Safety: x - 2h is 0 or 1, which pins h
    let h = unsafe { half_hint(x) };
    let rest = x - 2 * h;
    assert(rest < 2);
    h
}
