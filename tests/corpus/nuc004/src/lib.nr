// NUC-004 One-sided is-zero: `x * flag == 0` without the inverse check.

unconstrained fn is_zero_flag(x: Field) -> bool {
    x == 0
}

unconstrained fn is_zero_field(x: Field) -> Field {
    if x == 0 { 1 } else { 0 }
}

unconstrained fn is_zero_full(x: Field) -> (Field, Field) {
    if x == 0 { (1, 0) } else { (0, 1 / x) }
}

// expect: NUC-004
pub fn vuln_1(x: Field) -> bool {
    // Safety: x * flag == 0 below
    let flag = unsafe { is_zero_flag(x) };
    assert(x * (flag as Field) == 0);
    flag
}

// expect: NUC-004
pub fn vuln_2(x: Field) -> Field {
    // Safety: x * flag == 0 below
    let flag = unsafe { is_zero_field(x) };
    assert(x * flag == 0);
    flag
}

// expect: NUC-004
pub fn vuln_3(x: Field) -> Field {
    // Safety: the flag is boolean and x * flag == 0
    let flag = unsafe { is_zero_field(x) };
    assert(flag * (1 - flag) == 0);
    assert(flag * x == 0);
    flag
}

// expect: NUC-004
pub fn vuln_4(x: Field) -> Field {
    // Safety: x * flag == 0 below; the inverse is not used
    let (flag, _inv) = unsafe { is_zero_full(x) };
    assert(x * flag == 0);
    1 - flag
}

// expect: NUC-004
pub fn vuln_5(a: Field, b: Field) -> Field {
    // Safety: (a - b) * flag == 0 below
    let flag = unsafe { is_zero_field(a - b) };
    assert((a - b) * flag == 0);
    flag
}

// expect: NUC-004
pub fn vuln_6(x: Field) -> Field {
    // Safety: x * inv == 1 - flag below; the other side is missing
    let (flag, inv) = unsafe { is_zero_full(x) };
    assert(x * inv == 1 - flag);
    flag
}

// expect: NUC-004
pub fn vuln_7(a: Field, b: Field) -> Field {
    // Safety: (a - b) * inv + flag == 1 below; the other side is missing
    let (flag, inv) = unsafe { is_zero_full(a - b) };
    assert((a - b) * inv + flag == 1);
    flag
}

pub fn safe_1(x: Field) -> Field {
    // Safety: x * inv == 1 - flag and x * flag == 0 pin the flag
    let (flag, inv) = unsafe { is_zero_full(x) };
    assert(x * inv == 1 - flag);
    assert(x * flag == 0);
    flag
}

pub fn safe_2(x: Field) -> Field {
    // Safety: boolean flag plus both is-zero constraints
    let (flag, inv) = unsafe { is_zero_full(x) };
    assert(flag * (1 - flag) == 0);
    assert(x * flag == 0);
    assert(x * inv + flag == 1);
    flag
}

pub fn safe_3(x: Field) -> bool {
    x == 0
}

pub fn safe_4(x: Field) -> Field {
    // Safety: the flag is recomputed in constrained code
    let flag = unsafe { is_zero_field(x) };
    assert(x * flag == 0);
    assert(flag == (x == 0) as Field);
    flag
}

pub fn safe_5(a: Field, b: Field) -> Field {
    // Safety: full is-zero gadget on a - b
    let (flag, inv) = unsafe { is_zero_full(a - b) };
    assert((a - b) * inv == 1 - flag);
    assert((a - b) * flag == 0);
    flag
}

// The look-alikes accept honest witnesses (run with `nargo test`).
#[test]
fn honest_inputs_pass() {
    let _ = safe_1(0);
    let _ = safe_1(5);
    let _ = safe_2(0);
    let _ = safe_2(5);
    let _ = safe_3(0);
    let _ = safe_4(0);
    let _ = safe_4(5);
    let _ = safe_5(3, 3);
    let _ = safe_5(3, 4);
}
