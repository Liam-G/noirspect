// NUC-002 Missing remainder bound: quotient/remainder hints checked with
// `q * d + r == n` but no `r < d`.

unconstrained fn divmod32(n: u32, d: u32) -> (u32, u32) {
    (n / d, n % d)
}

unconstrained fn divmod64(n: u64, d: u64) -> (u64, u64) {
    (n / d, n % d)
}

// expect: NUC-002
pub fn vuln_1(n: u32, d: u32) -> u32 {
    // Safety: q and r are checked below
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    q
}

// expect: NUC-002
pub fn vuln_2(n: u64, d: u64) -> u64 {
    // Safety: recombined below
    let (q, r) = unsafe { divmod64(n, d) };
    assert(r + q * d == n);
    q
}

// expect: NUC-002
pub fn vuln_3(n: u64, d: u64) -> u64 {
    // Safety: recombined below
    let (q, r) = unsafe { divmod64(n, d) };
    assert(n == d * q + r);
    q
}

// expect: NUC-002
pub fn vuln_4(n: u32, d: u32) -> u32 {
    // Safety: off-by-one bound below
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    assert(r <= d);
    q
}

// expect: NUC-002
pub fn vuln_5(n: u32, d: u32) -> u32 {
    // Safety: bounded against the wrong value
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    assert(r < n);
    q
}

pub fn safe_1(n: u32, d: u32) -> u32 {
    // Safety: q * d + r == n and r < d pin both values
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    assert(r < d);
    q
}

pub fn safe_2(n: u64, d: u64) -> u64 {
    // Safety: q * d + r == n and d > r pin both values
    let (q, r) = unsafe { divmod64(n, d) };
    assert(d > r);
    assert(r + q * d == n);
    q
}

pub fn safe_3(n: u32, d: u32) -> u32 {
    // Safety: the checked subtraction proves r < d
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    let gap = d - r - 1;
    assert(gap < d);
    q
}

pub fn safe_4(n: u32, d: u32) -> u32 {
    n / d
}

pub fn safe_5(n: u32, d: u32) -> u32 {
    // Safety: q * d + r == n and r < d (compared as u64) pin both values
    let (q, r) = unsafe { divmod32(n, d) };
    assert(q * d + r == n);
    assert((r as u64) < (d as u64));
    q
}
