// NUC-003 Unchecked decomposition: limbs recombined into an input without
// a range check to their width.

unconstrained fn bits_hint(x: Field) -> [Field; 4] {
    let bits: [bool; 4] = x.to_le_bits();
    let mut out = [0; 4];
    for i in 0..4 { out[i] = bits[i] as Field; }
    out
}

unconstrained fn bool_bits_hint(x: Field) -> [bool; 8] {
    x.to_le_bits()
}

unconstrained fn bytes_hint(x: Field) -> [Field; 4] {
    let bytes: [u8; 4] = x.to_le_bytes();
    let mut out = [0; 4];
    for i in 0..4 { out[i] = bytes[i] as Field; }
    out
}

unconstrained fn u8_bytes_hint(x: Field) -> [u8; 4] {
    x.to_le_bytes()
}

unconstrained fn split_hint(x: Field) -> (Field, Field) {
    let lo = (x as u128) as Field;
    (lo, (x - lo) / 340282366920938463463374607431768211456)
}

global TWO_POW_128: Field = 340282366920938463463374607431768211456;
// The BN254 scalar field modulus, as 128-bit limbs.
global PLO: Field = 53438638232309528389504892708671455233;
global PHI: Field = 64323764613183177041862057485226039389;

unconstrained fn lte_hint(a: Field, b: Field) -> bool {
    (a as u128) <= (b as u128)
}

unconstrained fn limbs64_hint(x: Field) -> [u64; 2] {
    let v = x as u64;
    [v & 0xffffffff, v >> 32]
}

// expect: NUC-003
pub fn vuln_1(x: Field) {
    // Safety: bits are recombined below
    let bits = unsafe { bits_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..4 {
        acc += bits[i] * pow;
        pow *= 2;
    }
    assert(acc == x);
}

// expect: NUC-003
pub fn vuln_2(x: Field) {
    // Safety: bytes are recombined below
    let b = unsafe { bytes_hint(x) };
    assert(b[0] + b[1] * 256 + b[2] * 65536 + b[3] * 16777216 == x);
}

// expect: NUC-003
pub fn vuln_3(x: Field) {
    // Safety: hi and lo are recombined below
    let (lo, hi) = unsafe { split_hint(x) };
    hi.assert_max_bit_size::<128>();
    assert(lo + hi * 340282366920938463463374607431768211456 == x);
}

// expect: NUC-003
pub fn vuln_4(x: Field) {
    // Safety: 32-bit limbs are recombined below
    let l = unsafe { limbs64_hint(x) };
    assert((l[0] as Field) + (l[1] as Field) * 4294967296 == x);
}

// expect: NUC-003
pub fn vuln_5(x: Field) {
    // Safety: bits are checked to be 0 or 1, except one
    let bits = unsafe { bits_hint(x) };
    assert(bits[0] * (1 - bits[0]) == 0);
    assert(bits[1] * (1 - bits[1]) == 0);
    assert(bits[3] * (1 - bits[3]) == 0);
    assert(bits[0] + bits[1] * 2 + bits[2] * 4 + bits[3] * 8 == x);
}

// expect: NUC-003
pub fn vuln_6(x: Field) {
    // Safety: both halves are range checked to 128 bits and recombined
    let (lo, hi) = unsafe { split_hint(x) };
    lo.assert_max_bit_size::<128>();
    hi.assert_max_bit_size::<128>();
    assert(lo + hi * 340282366920938463463374607431768211456 == x);
}

pub fn safe_1(x: Field) {
    // Safety: every bit is checked to be 0 or 1 and recombined
    let bits = unsafe { bits_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..4 {
        assert(bits[i] * (1 - bits[i]) == 0);
        acc += bits[i] * pow;
        pow *= 2;
    }
    assert(acc == x);
}

pub fn safe_2(x: Field) {
    // Safety: u8 outputs are range checked; recombined below
    let b = unsafe { u8_bytes_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..4 {
        acc += (b[i] as Field) * pow;
        pow *= 256;
    }
    assert(acc == x);
}

pub fn safe_3(x: Field) {
    // Safety: bool outputs are range checked; recombined below
    let bits = unsafe { bool_bits_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..8 {
        acc += (bits[i] as Field) * pow;
        pow *= 2;
    }
    assert(acc == x);
}

pub fn safe_4(x: Field) {
    // Safety: every byte is range checked to 8 bits and recombined
    let b = unsafe { bytes_hint(x) };
    for i in 0..4 {
        b[i].assert_max_bit_size::<8>();
    }
    assert(b[0] + b[1] * 256 + b[2] * 65536 + b[3] * 16777216 == x);
}

pub fn safe_5(x: Field) {
    // Safety: a 248-bit value split into 128 and 120 bits, which stays below the modulus
    let (lo, hi) = unsafe { split_hint(x) };
    lo.assert_max_bit_size::<128>();
    hi.assert_max_bit_size::<120>();
    assert(lo + hi * 340282366920938463463374607431768211456 == x);
}

pub fn safe_6(x: Field) {
    // Safety: both halves are range checked, recombined, and compared to the
    // modulus limbs, like std::field::bn254::decompose
    let (lo, hi) = unsafe { split_hint(x) };
    lo.assert_max_bit_size::<128>();
    hi.assert_max_bit_size::<128>();
    assert(lo + hi * TWO_POW_128 == x);
    // Safety: the borrow is boolean by type; the range checks below fail unless (hi, lo) < p
    let borrow = unsafe { lte_hint(PLO, lo) };
    let rlo = PLO - lo - 1 + (borrow as Field) * TWO_POW_128;
    let rhi = PHI - hi - (borrow as Field);
    rlo.assert_max_bit_size::<128>();
    rhi.assert_max_bit_size::<128>();
}

// The look-alikes accept honest witnesses (run with `nargo test`).
#[test]
fn honest_inputs_pass() {
    safe_1(11);
    safe_2(0x12345678);
    safe_3(200);
    safe_4(0x01020304);
    safe_5(5);
    safe_6(5);
    safe_6(-1);
}
