// Copyright (C) 2018 NuCypher
//
// This file is part of goUmbral.
//
// goUmbral is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// goUmbral is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with goUmbral. If not, see <https://www.gnu.org/licenses/>.
//
// This file wraps OpenSSL functions that are relevant to Umbral.
//
// Most of these functions will return errors if they exist.
//
// If there is an error then an OpenSSLError will be returned,
// otherwise the functions will return a nil error.
package openssl

// #include "shim.h"
import "C"

// SizeOfBN wraps BN_num_bytes.
func SizeOfBN(bn BigNum) int {
    // BN_num_bytes is a macro for this.
    return int((C.BN_num_bits(bn)+7)/8)
}

// CmpBN wraps BN_cmp.
func CmpBN(a, b BigNum) int {
    return int(C.BN_cmp(a, b))
}

// AddBN wraps BN_add.
func AddBN(r, a, b BigNum) error {
    result := C.BN_add(r, a, b)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// SubBN wraps BN_sub.
func SubBN(r, a, b BigNum) error {
    result := C.BN_sub(r, a, b)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// MulBN wraps BN_mul.
func MulBN(r, a, b BigNum, ctx BNCtx) error {
    result := C.BN_mul(r, a, b, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// DivBN wraps BN_div.
func DivBN(dv, rem, a, d BigNum, ctx BNCtx) error {
    result := C.BN_div(dv, rem, a, d, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// MulBN wraps BN_mod.
func ModBN(rem, a, d BigNum, ctx BNCtx) error {
    // BN_mod() is a macro for this.
    err := DivBN(nil, rem, a, d, ctx)
    if err != nil {
        return err
    }
    return nil
}

// ModAddBN wraps BN_mod_add.
func ModAddBN(r, a, b, m BigNum, ctx BNCtx) error {
    result := C.BN_mod_add(r, a, b, m, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// ModSubBN wraps BN_mod_sub.
func ModSubBN(r, a, b, m BigNum, ctx BNCtx) error {
    result := C.BN_mod_sub(r, a, b, m, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// ModExpMontBN wraps BN_mod_exp_mont.
func ModExpMontBN(r, a, b, m BigNum, ctx BNCtx) error {
    var montCtx BNMontCtx = TmpBNMontCTX(m)
    defer FreeBNMontCtx(montCtx)

    result := C.BN_mod_exp_mont_consttime(r, a, b, m, ctx, montCtx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// ModMulBN wraps BN_mod_mul.
func ModMulBN(r, a, b, m BigNum, ctx BNCtx) error {
    result := C.BN_mod_mul(r, a, b, m, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// ModInvertBN wraps BN_mod_inverse.
func ModInvertBN(r, a, n BigNum, ctx BNCtx) error {
    result := C.BN_mod_inverse(r, a, n, ctx)
    if result == nil {
        return NewOpenSSLError()
    }
    return nil
}

// ModNegBN negates 'a' and places the result in 'r'.
func ModNegBN(r, a, m BigNum, ctx BNCtx) error {
    var zero BigNum = IntToBN(0)
    defer FreeBigNum(zero)

    result := C.BN_mod_sub(r, zero, a, m, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// ModModBN wraps BN_nnmod.
func ModModBN(r, a, m BigNum, ctx BNCtx) error {
    result := C.BN_nnmod(r, a, m, ctx)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}

// RandRangeBN wraps BN_rand_range and places a cryptographically
// strong pseudo-random number in 'r' in the range 0 <= 'r' < 'max'.
func RandRangeBN(r, max BigNum) error {
    result := C.BN_rand_range(r, max)
    if result != 1 {
        return NewOpenSSLError()
    }
    return nil
}
