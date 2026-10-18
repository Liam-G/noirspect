// NUC-006 Half-checked sort: order checked without permutation, or the reverse.

unconstrained fn sort_hint(a: [u32; 4]) -> [u32; 4] {
    a.sort()
}

unconstrained fn sort_desc_hint(a: [u32; 4]) -> [u32; 4] {
    a.sort_via(|x: u32, y: u32| x >= y)
}

unconstrained fn sort_index_hint(a: [u32; 4]) -> [u32; 4] {
    let s = a.sort();
    let mut idx = [0; 4];
    let mut used = [false; 4];
    for i in 0..4 {
        for j in 0..4 {
            if !used[j] & (a[j] == s[i]) & (idx[i] == 0) & !((i != 0) & (idx[i] != 0)) {
                idx[i] = j;
                used[j] = true;
            }
        }
    }
    idx
}

// expect: NUC-006
pub fn vuln_1(a: [u32; 4]) {
    // Safety: the output is checked to be ordered
    let s = unsafe { sort_hint(a) };
    for i in 0..3 {
        assert(s[i] <= s[i + 1]);
    }
}

// expect: NUC-006
pub fn vuln_2(a: [u32; 4]) {
    // Safety: strictly increasing output
    let s = unsafe { sort_hint(a) };
    for i in 0..3 {
        assert(s[i] < s[i + 1]);
    }
}

// expect: NUC-006
pub fn vuln_3(a: [u32; 4]) {
    // Safety: the output is checked to be descending
    let s = unsafe { sort_desc_hint(a) };
    for i in 0..3 {
        assert(s[i] >= s[i + 1]);
    }
}

// expect: NUC-006
pub fn vuln_4(a: [u32; 4]) {
    // Safety: same sum as the input
    let s = unsafe { sort_hint(a) };
    assert(s[0] + s[1] + s[2] + s[3] == a[0] + a[1] + a[2] + a[3]);
}

// expect: NUC-006
pub fn vuln_5(a: [u32; 4]) {
    // Safety: the first element is the smallest
    let s = unsafe { sort_hint(a) };
    assert(s[0] <= s[1]);
    assert(s[0] <= s[2]);
    assert(s[0] <= s[3]);
}

pub fn safe_1(a: [u32; 4]) {
    // Safety: ordered, and each element is the input at a hinted index
    let s = unsafe { sort_hint(a) };
    let idx = unsafe { sort_index_hint(a) };
    for i in 0..3 {
        assert(s[i] <= s[i + 1]);
    }
    for i in 0..4 {
        assert(s[i] == a[idx[i]]);
    }
}

pub fn safe_2(a: [u32; 4]) {
    // Safety: ordered, and the multiset matches at a fixed challenge
    let s = unsafe { sort_hint(a) };
    for i in 0..3 {
        assert(s[i] <= s[i + 1]);
    }
    let r = 1234567;
    let mut ps = 1;
    let mut pa = 1;
    for i in 0..4 {
        ps *= r - (s[i] as Field);
        pa *= r - (a[i] as Field);
    }
    assert(ps == pa);
}

pub fn safe_3(a: [u32; 4]) -> [u32; 4] {
    a.sort()
}

pub fn safe_4(a: [u32; 4]) {
    // Safety: ordered, and sum and sum of squares match the input
    let s = unsafe { sort_hint(a) };
    for i in 0..3 {
        assert(s[i] <= s[i + 1]);
    }
    let mut d1 = 0;
    let mut d2 = 0;
    for i in 0..4 {
        d1 += (s[i] as Field) - (a[i] as Field);
        d2 += (s[i] as Field) * (s[i] as Field) - (a[i] as Field) * (a[i] as Field);
    }
    assert(d1 == 0);
    assert(d2 == 0);
}

pub fn safe_5(a: [u32; 4]) {
    // Safety: descending, and each element is the input at a hinted index
    let s = unsafe { sort_desc_hint(a) };
    let idx = unsafe { sort_index_hint(a) };
    for i in 0..3 {
        assert(s[i] >= s[i + 1]);
    }
    for i in 0..4 {
        assert(s[i] == a[idx[3 - i]]);
    }
}
