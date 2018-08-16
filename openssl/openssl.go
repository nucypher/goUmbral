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
package openssl

// #include "shim.h"
import "C"
import (
    "unsafe"
    "math/big"
    "log"
)

type BigNum *C.BIGNUM
type BNCtx *C.BN_CTX
type BNMontCtx *C.BN_MONT_CTX
type ECGroup *C.EC_GROUP
type ECPoint *C.EC_POINT

func NewBigNum() BigNum {
    // bn must be freed later by the calling function.
    var bn BigNum = C.BN_secure_new()
    if bn == nil {
        log.Panic(NewOpenSSLError())
    }
    C.BN_set_flags(bn, C.BN_FLG_CONSTTIME)
    // Both BN_FLG_CONSTTIME and BN_FLG_SECURE are set.
    return bn
}

func NewBNCtx() BNCtx {
    var ctx BNCtx = C.BN_CTX_secure_new()
    if ctx == nil {
        log.Panic(NewOpenSSLError())
    }
    return ctx
}

func NewBNMontCtx() BNMontCtx {
    var montCtx BNMontCtx = C.BN_MONT_CTX_new()
    if montCtx == nil {
        log.Panic(NewOpenSSLError())
    }
    return montCtx
}

func NewECPoint(curve *Curve) (ECPoint, error) {
    // newPoint must be freed later by the calling function.
    newPoint := C.EC_POINT_new(curve.Group)
    if newPoint == nil {
        // Invalid Curve Group: New EC Point Failed.
        return nil, NewOpenSSLError()
    }
    return newPoint, nil
}

func FreeBigNum(bn BigNum) {
    C.BN_clear_free(bn)
}

func FreeECPoint(point ECPoint) {
    C.EC_POINT_clear_free(point)
}

func FreeECGroup(group ECGroup) {
    C.EC_GROUP_free(group)
}

func FreeBNCtx(ctx BNCtx) {
    C.BN_CTX_free(ctx)
}

func FreeBNMontCtx(montCtx BNMontCtx) {
    C.BN_MONT_CTX_free(montCtx)
}

func GetECGroupByCurveNID(curveNid C.int) (ECGroup, error) {
    // curve must be freed later by the calling function.
    var curve ECGroup = C.EC_GROUP_new_by_curve_name(curveNid)
    if curve == nil {
        // Invalid Curve NID: Curve Group Lookup Failed.
        return nil, NewOpenSSLError()
    }
    return curve, nil
}

func GetECOrderByGroup(group ECGroup) (BigNum, error) {
    // order must be freed later by the calling function.
    var order BigNum = NewBigNum()

    var ctx BNCtx = NewBNCtx()
    defer FreeBNCtx(ctx)

    result := C.EC_GROUP_get_order(group, order, ctx)
    if result != 1 {
        // Invalid Group: Curve Order Lookup Failed.
        return nil, NewOpenSSLError()
    }
    return order, nil
}

func GetECGeneratorByGroup(group ECGroup) (ECPoint, error) {
    // generator should not be freed directly by the calling function.
    // Free the ECGroup instead.
    var generator ECPoint = C.EC_GROUP_get0_generator(group)

    if generator == nil {
        // Invalid Group: Generator Lookup Failed.
        return nil, NewOpenSSLError()
    }
    return generator, nil
}

func GetECGroupDegree(group ECGroup) uint {
    return uint(C.EC_GROUP_get_degree(group))
}

func BNIsWithinOrder(checkBN BigNum, curve *Curve) bool {
    zero, err := IntToBN(0)
    if err != nil {
        return false
    }
    defer FreeBigNum(zero)

    checkSign := C.BN_cmp(checkBN, zero)
    rangeCheck := C.BN_cmp(checkBN, curve.Order)

    return checkSign == 1 && rangeCheck == -1
}

func GetECPointFromAffine(affineX, affineY BigNum, curve *Curve) (ECPoint, error) {
    // newPoint must be freed later by the calling function.
    newPoint, err := NewECPoint(curve)
    if err != nil {
        return nil, err
    }

    var ctx BNCtx = NewBNCtx()
    defer FreeBNCtx(ctx)

    result := C.EC_POINT_set_affine_coordinates_GFp(
            curve.Group, newPoint, affineX, affineY, ctx)
    if result != 1 {
        // Invalid Affine or Curve: EC Point Lookup Failed.
        return nil, NewOpenSSLError()
    }
    return newPoint, nil
}

func GetAffineCoordsFromECPoint(point ECPoint, curve *Curve) (BigNum, BigNum, error) {
    // affineX and affineY must be freed later by the calling function.
    var affineX BigNum = NewBigNum()
    var affineY BigNum = NewBigNum()

    var ctx BNCtx = NewBNCtx()
    defer FreeBNCtx(ctx)

    result := C.EC_POINT_get_affine_coordinates_GFp(
            curve.Group, point, affineX, affineY, ctx)
    if result != 1 {
        // Invalid ECPoint or Curve: Affine Lookup Failed.
        return nil, nil, NewOpenSSLError()
    }
    return affineX, affineY, nil
}

func TmpBNMontCTX(modulus BigNum) (BNMontCtx, error) {
    var ctx BNCtx = NewBNCtx()
    defer FreeBNCtx(ctx)

    // montCtx must be freed later by the calling function.
    var montCtx BNMontCtx = NewBNMontCtx()

    result := C.BN_MONT_CTX_set(montCtx, modulus, ctx)
    if result != 1 {
        // Set Montgomery CTX With Modulus Failed.
        return nil, NewOpenSSLError()
    }
    return montCtx, nil
}

func IntToBN(sInt int) (BigNum, error) {
    var bInt *big.Int = big.NewInt(int64(sInt))
    return BigIntToBN(bInt)
}

func BigIntToBN(bInt *big.Int) (BigNum, error) {
    var goIntAsBytes []byte = bInt.Bytes()
    return BytesToBN(goIntAsBytes)
}

func BNToBigInt(bn BigNum) (*big.Int, error) {
    bytes, err := BNToBytes(bn)
    if err != nil {
        return nil, err
    }
    var bInt *big.Int = big.NewInt(0)
    bInt.SetBytes(bytes)
    return bInt, nil
}

func BytesToBigInt(bytes []byte) *big.Int {
    var bInt *big.Int = big.NewInt(0)
    bInt.SetBytes(bytes)
    return bInt
}

func BytesToBN(bytes []byte) (BigNum, error) {
    cBytes := C.CBytes(bytes)
    defer C.free(cBytes)
    // cBN must be freed later by the calling function.
    var cBN BigNum = C.BN_bin2bn((*C.uint8_t)(cBytes), C.int(len(bytes)), NewBigNum())
    if cBN == nil {
        // Deserialization Failed.
        return nil, NewOpenSSLError()
    }
    return cBN, nil
}

func BNToBytes(cBN BigNum) ([]byte, error) {
    var size int = SizeOfBN(cBN)
    var space []byte = make([]byte, size)
    cSpace := C.CBytes(space)
    defer C.free(cSpace)

    var written C.int = C.BN_bn2bin(cBN, (*C.uint8_t)(cSpace))
    if int(written) != size {
        // Invalid Written Size: Serialization Failed.
        return nil, NewOpenSSLError()
    }
    bytes := C.GoBytes(cSpace, written)
    return bytes, nil
}

func BNToDecStr(cBN BigNum) string {
    cString := C.BN_bn2dec(cBN)
    if cString == nil {
        log.Print(NewOpenSSLError())
        return ""
    }
    defer C.free(unsafe.Pointer(cString))

    return C.GoString(cString)
}
