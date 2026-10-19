// NUC-007 Narrowing cast of an unchecked Field (off by default).

unconstrained fn field_hint(x: Field) -> Field {
    x * 2
}

// expect: NUC-007
pub fn vuln_1(x: Field) -> u8 {
    x as u8
}

// expect: NUC-007
pub fn vuln_2(x: Field) -> u32 {
    // Safety: doubled in the hint, then narrowed
    let y = unsafe { field_hint(x) };
    assert(y == x * 2);
    y as u32
}

// expect: NUC-007
pub fn vuln_3(x: Field, y: Field) -> u16 {
    (x + y) as u16
}

// expect: NUC-007
pub fn vuln_4(arr: [Field; 3]) -> u8 {
    arr[1] as u8
}

// expect: NUC-007
pub fn vuln_5(x: Field, limit: u64) {
    assert((x as u64) < limit);
}

pub fn safe_1(x: Field) -> u8 {
    x.assert_max_bit_size::<8>();
    x as u8
}

pub fn safe_2(x: u32) -> u8 {
    x as u8
}

pub fn safe_3(x: u8) -> u8 {
    let f = x as Field;
    f as u8
}

pub fn safe_4(x: Field) -> u16 {
    x.assert_max_bit_size::<16>();
    x as u16
}

pub fn safe_5(x: Field) -> u8 {
    let bytes: [u8; 32] = x.to_le_bytes();
    bytes[0]
}

// The look-alikes accept honest witnesses (run with `nargo test`).
#[test]
fn honest_inputs_pass() {
    let _ = safe_1(200);
    let _ = safe_2(300);
    let _ = safe_3(7);
    let _ = safe_4(60000);
    let _ = safe_5(5);
}
