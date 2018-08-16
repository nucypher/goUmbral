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
package math

import (
    "errors"
    "log"
    "golang.org/x/crypto/blake2b"
    "github.com/nucypher/goUmbral/openssl"
)

/*
Represents an OpenSSL BIGNUM modulo the order of a curve. Some of these
operations will only work with prime numbers
*/

type ModBigNum struct {
   Bignum openssl.BigNum
   Curve *openssl.Curve
}

func GetNewModBN(cNum openssl.BigNum, curve *openssl.Curve) (*ModBigNum, error) {
    // Return the ModBigNum only if the provided Bignum is within the order of the curve.
    if !openssl.BNIsWithinOrder(cNum, curve) {
        return nil, errors.New("The provided BIGNUM is not on the provided curve.")
    }
    return &ModBigNum{Bignum: cNum, Curve: curve}, nil
}

func ExpectedBytesLength(curve *openssl.Curve) {
    // TODO: Return the size of a modbn given the curve.
}

func GenRandModBN(curve *openssl.Curve) (*ModBigNum, error) {
    /*
    Returns a ModBigNum with a openssl.raphically secure OpenSSL BIGNUM
    based on the given curve.
    */

    // newRandBN needs to be from 1 inclusive to curve exclusive
    if curve.Order == nil {
        return nil, errors.New("The order of the curve is nil. Construct a valid curve first.")
    }
    newRandBN := openssl.NewBigNum()
    err := openssl.RandRangeBN(newRandBN, curve.Order)
    if err != nil {
        return nil, err
    }

    if !openssl.BNIsWithinOrder(newRandBN, curve) {
        openssl.FreeBigNum(newRandBN)
        return GenRandModBN(curve)
    }
    return &ModBigNum{Bignum: newRandBN, Curve: curve}, nil
}

func Int2ModBN(num int, curve *openssl.Curve) (*ModBigNum, error) {
    newBN, err := openssl.IntToBN(num)
    if err != nil {
        return nil, err
    }
    if !openssl.BNIsWithinOrder(newBN, curve) {
        return nil, errors.New("Bignum is not within the curve")
    }

    return &ModBigNum{Bignum: newBN, Curve: curve}, nil
}

func Hash2ModBN(bytes []byte, params UmbralParameters) (*ModBigNum, error) {
    // Returns a ModBigNum based on provided data hashed by blake2b.
    hash := blake2b.Sum512(bytes)
    hashBN, err := openssl.BytesToBN(hash[:])
    if err != nil {
        return nil, err
    }

    oneBN, err := openssl.IntToBN(1)
    if err != nil {
        return nil, err
    }
    defer openssl.FreeBigNum(oneBN)

    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    result := openssl.NewBigNum()

    err = openssl.SubBN(result, params.Curve.Order, oneBN)
    if err != nil {
        return nil, err
    }

    err = openssl.ModBN(result, hashBN, result, ctx)
    if err != nil {
        return nil, err
    }

    err = openssl.AddBN(result, result, oneBN)
    if err != nil {
        return nil, err
    }

    return &ModBigNum{Bignum: result, Curve: params.Curve}, nil
}

func Bytes2ModBN(data []byte, curve *openssl.Curve) (*ModBigNum, error) {
    // Returns the ModBigNum associated with the bytes-converted bignum
    // provided by the data argument.
    if len(data) == 0 {
        return nil, errors.New("No bytes failure")
    }

    bignum, err := openssl.BytesToBN(data)
    if err != nil {
        return nil, err
    }
    if !openssl.BNIsWithinOrder(bignum, curve) {
        return nil, errors.New("Bignum is not within the curve")
    }

    return &ModBigNum{Bignum: bignum, Curve: curve}, nil
}

func (m *ModBigNum) Bytes() ([]byte, error) {
    return openssl.BNToBytes(m.Bignum)
}

func (m *ModBigNum) Equals(other *ModBigNum) bool {
    return openssl.CmpBN(m.Bignum, other.Bignum) == 0
}

func (m ModBigNum) Compare(other *ModBigNum) int {
    // -1 less than, 0 is equal to, 1 is greater than
    return openssl.CmpBN(m.Bignum, other.Bignum)
}

// ModBigNum.Pow() will perform (x^y) modulo the order of the curve of x and y.
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Pow will log the error, and return nil.
func (z *ModBigNum) Pow(x, y *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(y.Curve) || !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Pow Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModExpMontBN(z.Bignum, x.Bignum, y.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Mul() will perform (x * y) modulo the order of the curve of x and y.
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Mul will log the error, and return nil.
func (z *ModBigNum) Mul(x, y *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(y.Curve) || !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Mul Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModMulBN(z.Bignum, x.Bignum, y.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Div() will perform (x / y) modulo the order of the curve of x and y.
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Div will log the error, and return nil.
func (z *ModBigNum) Div(x, y *ModBigNum) *ModBigNum {
    result := z.Invert(y)
    if result == nil {
        log.Print("ModBigNum Div Error: Invert Failed")
        return nil
    }

    result = z.Mul(z, x)
    if result == nil {
        log.Print("ModBigNum Div Error: Mul Failed")
        return nil
    }

    return z
}

// ModBigNum.Add() will perform (x + y) modulo the order of the curve of x and y.
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Add will log the error, and return nil.
func (z *ModBigNum) Add(x, y *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(y.Curve) || !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Add Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModAddBN(z.Bignum, x.Bignum, y.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Sub() will perform (x - y) modulo the order of the curve of x and y.
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Sub will log the error, and return nil.
func (z *ModBigNum) Sub(x, y *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(y.Curve) || !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Sub Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModSubBN(z.Bignum, x.Bignum, y.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Invert() computes (x*z)%m==1 where m is the order of the curve of x and z.
// It will then set z to the result of that operation and return it.
//
// x and z must use the same curve and must be initialized.
//
// On error, Invert will log the error, and return nil.
func (z *ModBigNum) Invert(x *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Invert Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModInvertBN(z.Bignum, x.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Neg() computes the modular opposite (i. e., additive inverse) of x.
// It will then set z to the result of that operation and return it.
//
// x and z must use the same curve and must be initialized.
//
// On error, Neg will log the error, and return nil.
func (z *ModBigNum) Neg(x *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Neg Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModNegBN(z.Bignum, x.Bignum, x.Curve.Order, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

// ModBigNum.Mod() will perform (x % y).
// It will then set z to the result of that operation and return it.
//
// x, y, and z must use the same curve and must be initialized.
//
// On error, Mod will log the error, and return nil.
func (z *ModBigNum) Mod(x, y *ModBigNum) *ModBigNum {
    if !x.Curve.Equals(y.Curve) || !x.Curve.Equals(z.Curve) {
        log.Print("ModBigNum Mod Error: The curves are not equal")
        return nil
    }
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    err := openssl.ModNegBN(z.Bignum, x.Bignum, y.Bignum, ctx)
    if err != nil {
        log.Print(err)
        return nil
    }
    return z
}

func (m *ModBigNum) Copy() (*ModBigNum, error) {
    // Deep copy of a ModBigNum EXCLUDING the curve.
    bn, err := openssl.DupBN(m.Bignum)
    if err != nil {
        return nil, err
    }
    return &ModBigNum{Bignum: bn, Curve: m.Curve}, nil
}

func (m *ModBigNum) Free() {
    openssl.FreeBigNum(m.Bignum)
}
