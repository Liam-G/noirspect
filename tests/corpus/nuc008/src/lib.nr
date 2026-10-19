// NUC-008 Empty safety comment.

unconstrained fn inv_hint(x: Field) -> Field {
    1 / x
}

// expect: NUC-008
pub fn vuln_1(x: Field) {
    // Safety:
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

// expect: NUC-008
pub fn vuln_2(x: Field) {
    // Safety: safe
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

// expect: NUC-008
pub fn vuln_3(x: Field) {
    // Safety: TODO
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

// expect: NUC-008
pub fn vuln_4(x: Field) {
    // SAFETY: trust me.
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

// expect: NUC-008
pub fn vuln_5(x: Field) {
    // Safety: n/a
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_1(x: Field) {
    // Safety: inv * x == 1 pins the inverse
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_2(x: Field) {
    // Safety:
    // the product with x is constrained to 1 below
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_3(x: Field) {
    // SAFETY: checked by the assertion on the next line
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_4(x: Field) {
    // Safety: safe because inv * x == 1 is asserted
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

pub fn safe_5(x: Field) {
    // Safety: a non-zero x has exactly one inverse, enforced below
    let inv = unsafe { inv_hint(x) };
    assert(inv * x == 1);
}

// The look-alikes accept honest witnesses (run with `nargo test`).
#[test]
fn honest_inputs_pass() {
    safe_1(5);
    safe_2(5);
    safe_3(5);
    safe_4(5);
    safe_5(5);
}
