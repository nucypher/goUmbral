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
package umbral

// #include "shim.h"
import "C"
import (
    "unsafe"
    "golang.org/x/crypto/blake2b"
    "errors"
)

/*
Represents an OpenSSL BIGNUM modulo the order of a curve. Some of these
operations will only work with prime numbers
*/

type ModBigNum struct {
   Bignum BigNum
   Curve Curve
}

func GetNewModBN(cNum BigNum, curve Curve) (ModBigNum, error) {
    // Return the ModBigNum only if the provided Bignum is within the order of the curve.
    if !BNIsWithinOrder(cNum, curve) {
        return ModBigNum{}, errors.New("The provided BIGNUM is not on the provided curve.")
    }
    return ModBigNum{Bignum: cNum, Curve: curve}, nil
}

func ExpectedBytesLength(curve Curve) {
    // TODO: Return the size of a modbn given the curve.
}

func GenRandModBN(curve Curve) (ModBigNum, error) {
    /*
    Returns a ModBigNum with a cryptographically secure OpenSSL BIGNUM
    based on the given curve.
    */

    // newRandBN needs to be from 1 inclusive to curve exclusive
    if curve.Order == nil {
        return ModBigNum{}, errors.New("The order of the curve is nil. Construct a valid curve first.")
    }
    newRandBN := RandRangeBN(curve.Order)

    if !BNIsWithinOrder(newRandBN, curve) {
        FreeBigNum(newRandBN)
        return GenRandModBN(curve)
    }
    return ModBigNum{Bignum: newRandBN, Curve: curve}, nil
}

func Int2ModBN(num int, curve Curve) (ModBigNum, error) {
    newBN := IntToBN(num)
    if !BNIsWithinOrder(newBN, curve) {
        return ModBigNum{}, errors.New("Bignum is not within the curve")
    }

    return ModBigNum{Bignum: newBN, Curve: curve}, nil
}

func Hash2ModBN(bytes []byte, curve Curve) (ModBigNum, error) {
    // Returns a ModBigNum based on provided data hashed by blake2b.
    hash := blake2b.Sum512(bytes)
    hashBN := BytesToBN(hash[:])

    oneBN := IntToBN(1)
    defer FreeBigNum(oneBN)

    orderMinusOne := SubBN(curve.Order, oneBN)
    defer FreeBigNum(orderMinusOne)

    moddedResult := ModBN(hashBN, orderMinusOne)
    defer FreeBigNum(moddedResult)

    bignum := AddBN(moddedResult, oneBN)

    return ModBigNum{Bignum: bignum, Curve: curve}, nil
}

func Bytes2ModBN(data []byte, curve Curve) (ModBigNum, error) {
    // Returns the ModBigNum associated with the bytes-converted bignum
    // provided by the data argument.
    if len(data) == 0 {
        return ModBigNum{}, errors.New("No bytes failure")
    }

    bignum := BytesToBN(data)
    if !BNIsWithinOrder(bignum, curve) {
        return ModBigNum{}, errors.New("Bignum is not within the curve")
    }

    return ModBigNum{Bignum: bignum, Curve: curve}, nil
}

func (m ModBigNum) ToBytes() []byte {
    return BNToBytes(m.Bignum)
}

func (m ModBigNum) Equals(other ModBigNum) bool {
    return CompareBN(m.Bignum, other.Bignum) == 0
}

func (m ModBigNum) Compare(other ModBigNum) int {
    // -1 less than, 0 is equal to, 1 is greater than
    return CompareBN(m.Bignum, other.Bignum)
}

func (m *ModBigNum) Pow(other ModBigNum) error {
    /*
    Performs a BN_mod_exp on two BIGNUMS.
    WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
    */
    power := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    bnMontCtx := TmpBNMontCTX(m.Curve.Order)
    defer FreeBNMontCTX(bnMontCtx)
    result := C.BN_mod_exp_mont_consttime(power,
        m.Bignum, other.Bignum, m.Curve.Order, bnCtx, bnMontCtx)

    if result != 1 {
        return errors.New("BN_mod_exp failure")
    }

    FreeBigNum(m.Bignum)

    m.Bignum = power
    return nil
}

func (m *ModBigNum) Mul(other ModBigNum) error {
    /*
    Performs a BN_mod_mul between two BIGNUMS.
    */
    product := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_mul(product, m.Bignum, other.Bignum, m.Curve.Order, bnCtx)
    if result != 1 {
        return errors.New("BN_mod_mul failure")
    }
    FreeBigNum(m.Bignum)

    m.Bignum = product
    return nil
}

func (m *ModBigNum) Div(other ModBigNum) error {
    tmpBN, err := other.Copy()
    if err != nil {
        return err
    }
    defer tmpBN.Free()

    err = tmpBN.Invert()
    if err != nil {
        return err
    }

    err = m.Mul(tmpBN)
    if err != nil {
        return err
    }

    return nil
}

func (m *ModBigNum) Add(other ModBigNum) error {
    sum := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_add(sum, m.Bignum, other.Bignum, m.Curve.Order, bnCtx)
    if result != 1 {
        return errors.New("BN_mod_add failure")
    }

    FreeBigNum(m.Bignum)

    m.Bignum = sum
    return nil
}

func (m *ModBigNum) Sub(other ModBigNum) error {
    sub := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_sub(sub, m.Bignum, other.Bignum, m.Curve.Order, bnCtx)
    if result != 1 {
        return errors.New("BN_mod_sub failure")
    }

    FreeBigNum(m.Bignum)

    m.Bignum = sub
    return nil
}

func (m *ModBigNum) Invert() error {
    inverse := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_inverse(inverse, m.Bignum, m.Curve.Order, bnCtx)

    if unsafe.Pointer(result) == C.NULL {
        return errors.New("BN_mod_inverse failure")
    }

    FreeBigNum(m.Bignum)

    m.Bignum = inverse
    return nil
}

func (m *ModBigNum) Mod(other ModBigNum) error {
    rem := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_nnmod(rem, m.Bignum, other.Bignum, bnCtx)
    if result != 1 {
        return errors.New("BN_nnmod failure")
    }

    FreeBigNum(m.Bignum)

    m.Bignum = rem
    return nil
}

func (m ModBigNum) Copy() (ModBigNum, error) {
    // Deep copy of a ModBigNum EXCLUDING the curve.
    bn := C.BN_dup(m.Bignum)
    if unsafe.Pointer(bn) == C.NULL {
        return ModBigNum{}, errors.New("BN_dup failure")
    }
    return ModBigNum{Bignum: bn, Curve: m.Curve}, nil
}

func (m *ModBigNum) Free() {
    FreeBigNum(m.Bignum)
    // Do not free the curve.
    // m.Curve.Free()
}
