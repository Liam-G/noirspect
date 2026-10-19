// NUC-005 Unchecked index: a hinted index whose element is never compared to the needle.

unconstrained fn find_hint(arr: [Field; 4], needle: Field) -> u32 {
    let mut idx = 0;
    for i in 0..4 {
        if arr[i] == needle { idx = i; }
    }
    idx
}

unconstrained fn find_u8_hint(arr: [Field; 4], needle: Field) -> u8 {
    let mut idx = 0;
    for i in 0..4 {
        if arr[i] == needle { idx = i as u8; }
    }
    idx
}

// expect: NUC-005
pub fn vuln_1(arr: [Field; 4], needle: Field) {
    // Safety: the index is bounds checked
    let i = unsafe { find_hint(arr, needle) };
    let _e = arr[i];
}

// expect: NUC-005
pub fn vuln_2(arr: [Field; 4], needle: Field) {
    // Safety: the element is non-zero
    let i = unsafe { find_hint(arr, needle) };
    assert(arr[i] != 0);
}

// expect: NUC-005
pub fn vuln_3(arr: [Field; 4], needle: Field, other: Field) {
    // Safety: compared to the wrong value
    let i = unsafe { find_hint(arr, needle) };
    assert(arr[i] == other);
}

// expect: NUC-005
pub fn vuln_4(keys: [Field; 4], values: [Field; 4], key: Field) {
    // Safety: the value at the key's index is non-zero
    let i = unsafe { find_hint(keys, key) };
    assert(values[i] != 0);
}

// expect: NUC-005
pub fn vuln_5(arr: [Field; 4], needle: Field) {
    // Safety: the index is below the length
    let i = unsafe { find_hint(arr, needle) };
    assert(i < 4);
    let _e = arr[i];
}

pub fn safe_1(arr: [Field; 4], needle: Field) {
    // Safety: the element at the index equals the needle
    let i = unsafe { find_hint(arr, needle) };
    assert(arr[i] == needle);
}

pub fn safe_2(keys: [Field; 4], values: [Field; 4], key: Field) {
    // Safety: keys[i] == key ties the index to the key
    let i = unsafe { find_hint(keys, key) };
    assert(keys[i] == key);
    assert(values[i] != 0);
}

pub fn safe_3(arr: [Field; 4], needle: Field) {
    // Safety: the element at the u8 index equals the needle
    let i = unsafe { find_u8_hint(arr, needle) };
    assert(arr[i as u32] == needle);
}

pub fn safe_4(arr: [Field; 4], needle: Field) {
    // Safety: the difference is zero
    let i = unsafe { find_hint(arr, needle) };
    assert(arr[i] - needle == 0);
}

pub fn safe_5(arr: [Field; 4], needle: Field) {
    // Safety: the element equals needle + 1, which is what the caller searches for
    let i = unsafe { find_hint(arr, needle + 1) };
    assert(arr[i] == needle + 1);
}

// The look-alikes accept honest witnesses (run with `nargo test`).
#[test]
fn honest_inputs_pass() {
    let arr = [10, 20, 30, 40];
    safe_1(arr, 30);
    safe_2(arr, [1, 2, 3, 4], 30);
    safe_3(arr, 30);
    safe_4(arr, 30);
    safe_5(arr, 29);
}
