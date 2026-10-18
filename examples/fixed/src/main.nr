// The circuit from `examples/vulnerable` with every constraint in place.

unconstrained fn div_hint(n: u32, d: u32) -> (u32, u32) {
    (n / d, n % d)
}

fn div(n: u32, d: u32) -> u32 {
    // Safety: q * d + r == n with r < d has exactly one solution
    let (q, r) = unsafe { div_hint(n, d) };
    assert(q * d + r == n);
    assert(r < d);
    q
}

unconstrained fn is_zero_hint(x: Field) -> (Field, Field) {
    if x == 0 { (1, 0) } else { (0, 1 / x) }
}

fn is_zero(x: Field) -> Field {
    // Safety: x * inv == 1 - flag and x * flag == 0 force the flag both ways
    let (flag, inv) = unsafe { is_zero_hint(x) };
    assert(x * inv == 1 - flag);
    assert(x * flag == 0);
    flag
}

unconstrained fn bits_hint(x: Field) -> [bool; 8] {
    x.to_le_bits()
}

fn to_bits(x: Field) -> [bool; 8] {
    // Safety: bool outputs are range checked by the compiler; recombined below
    let bits = unsafe { bits_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..8 {
        acc += (bits[i] as Field) * pow;
        pow *= 2;
    }
    assert(acc == x);
    bits
}

fn main(n: u32, d: u32, x: Field, byte: Field) -> pub (u32, Field, [bool; 8]) {
    (div(n, d), is_zero(x), to_bits(byte))
}
