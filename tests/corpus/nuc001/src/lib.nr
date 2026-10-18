// NUC-001 Constant-only check: a hint result only ever compared to constants.

unconstrained fn verify_hint(sig: Field, msg: Field) -> bool {
    sig == msg * 7
}

unconstrained fn score_hint(x: Field) -> Field {
    if x == 3 { 1 } else { 0 }
}

unconstrained fn sqrt_hint(y: u64) -> u64 {
    let mut r: u64 = 0;
    for i in 0..32 {
        if (i as u64) * (i as u64) <= y { r = i as u64; }
    }
    r
}

unconstrained fn inv_hint(x: Field) -> Field {
    1 / x
}

unconstrained fn secret_hint() -> u32 {
    42
}

unconstrained fn max_hint(a: u32, b: u32) -> u32 {
    if a > b { a } else { b }
}

// expect: NUC-001
pub fn vuln_1(sig: Field, msg: Field) {
    // Safety: the hint verifies the signature
    let ok = unsafe { verify_hint(sig, msg) };
    assert(ok);
}

// expect: NUC-001
pub fn vuln_2(x: Field) {
    // Safety: the hint scores the input
    let score = unsafe { score_hint(x) };
    assert(score == 1);
}

// expect: NUC-001
pub fn vuln_3(y: u64) {
    // Safety: the root is range checked
    let r = unsafe { sqrt_hint(y) };
    assert(r < 1000);
}

// expect: NUC-001
pub fn vuln_4(sig: Field, msg: Field) {
    // Safety: the hint reports whether the signature is bad
    let bad = unsafe { verify_hint(sig, msg) };
    assert(!bad);
}

// expect: NUC-001
pub fn vuln_5(x: Field) {
    // Safety: the inverse is non-zero
    let inv = unsafe { inv_hint(x) };
    assert(inv != 0);
}

pub fn safe_1(y: u64) {
    // Safety: r * r <= y < (r + 1) * (r + 1) pins the root
    let r = unsafe { sqrt_hint(y) };
    assert(r < 4294967296);
    assert(r * r <= y);
    assert(y < (r + 1) * (r + 1));
}

pub fn safe_2() -> u32 {
    // Safety: a free private witness by design, only bounded
    let w = unsafe { secret_hint() };
    assert(w < 1000);
    w
}

pub fn safe_3(x: Field) {
    // Safety: inv * x == 1 pins the inverse
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_4(x: Field) {
    // Safety: the claim is recomputed in constrained code
    let score = unsafe { score_hint(x) };
    assert(score == (x == 3) as Field);
}

pub fn safe_5(a: u32, b: u32) -> u32 {
    // Safety: m is one of the inputs and not below either
    let m = unsafe { max_hint(a, b) };
    assert((m == a) | (m == b));
    assert(m >= a);
    assert(m >= b);
    m
}
