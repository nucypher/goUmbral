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
    "math/big"
    "log"
    "errors"
)

type BigNum *C.BIGNUM
type BNCtx *C.BN_CTX
type BNMontCtx *C.BN_MONT_CTX
type ECGroup *C.EC_GROUP
type ECPoint *C.EC_POINT

func GetBigNum() BigNum {
    // bn must be freed later by the calling function.
    var bn BigNum = C.BN_secure_new()
    C.BN_set_flags(bn, C.BN_FLG_CONSTTIME)
    // Both BN_FLG_CONSTTIME and BN_FLG_SECURE are set.
    return bn
}

func GetECGroupByCurveNID(curveNid int) ECGroup {
    // curve must be freed later by the calling function.
    var curve *C.EC_GROUP = C.EC_GROUP_new_by_curve_name(C.int(curveNid))
    if unsafe.Pointer(curve) == C.NULL {
        // Failure
        log.Fatal("Curve group lookup failed")
    }
    return curve
}

func GetECOrderByGroup(group ECGroup) BigNum {
    // order must be freed later by the calling function.
    var order BigNum = GetBigNum()

    var ctx *C.BN_CTX = C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := int(C.EC_GROUP_get_order(group, order, ctx))
    if result != 1 {
        // Failure
        log.Fatal("Curve order lookup failed")
    }
    return order
}

func GetECGeneratorByGroup(group ECGroup) ECPoint {
    // generator should not be freed directly by the calling function.
    // Free the EC_GROUP instead.
    var generator ECPoint = C.EC_GROUP_get0_generator(group)

    if unsafe.Pointer(generator) == C.NULL {
        // Failure
        log.Fatal("Generator failure")
    }
    return generator
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

func FreeBNCTX(ctx BNCtx) {
    C.BN_CTX_free(ctx)
}

func FreeBNMontCTX(montCtx BNMontCtx) {
    C.BN_MONT_CTX_free(montCtx)
}

func GetECGroupDegree(group ECGroup) uint {
    return uint(C.EC_GROUP_get_degree(group))
}

func BNIsWithinOrder(checkBN BigNum, curve Curve) bool {
    zero := IntToBN(0)
    defer FreeBigNum(zero)

    checkSign := C.BN_cmp(checkBN, zero)
    rangeCheck := C.BN_cmp(checkBN, curve.Order)

    return checkSign == 1 && rangeCheck == -1
}

func GetNewECPoint(curve Curve) (ECPoint, error) {
    // newPoint must be freed later by the calling function.
    newPoint := C.EC_POINT_new(curve.Group)
    if unsafe.Pointer(newPoint) == C.NULL {
        // Failure
        return newPoint, errors.New("New EC Point failure")
    }
    return newPoint, nil
}

func GetECPointFromAffine(affineX, affineY BigNum, curve Curve) (ECPoint, error) {
    // newPoint must be freed later by the calling function.
    newPoint, err := GetNewECPoint(curve)
    if err != nil {
        return newPoint, err
    }

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_set_affine_coordinates_GFp(
            curve.Group, newPoint, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        return newPoint, errors.New("EC Point lookup failure")
    }
    return newPoint, nil
}

func GetAffineCoordsFromECPoint(point ECPoint, curve Curve) (BigNum, BigNum, error) {
    // affineX and affineY must be freed later by the calling function.
    affineX := GetBigNum()
    affineY := GetBigNum()

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_get_affine_coordinates_GFp(
            curve.Group, point, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        return affineX, affineY, errors.New("Affine lookup failure")
    }
    return affineX, affineY, nil
}

func TmpBNMontCTX(modulus BigNum) BNMontCtx {
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    // montCtx must be freed later by the calling function.
    montCtx := C.BN_MONT_CTX_new()
    if unsafe.Pointer(montCtx) == C.NULL {
        log.Fatal("New Montgomery CTX allocation failure")
    }

    result := C.BN_MONT_CTX_set(montCtx, modulus, ctx)
    if result != 1 {
        log.Fatal("New Montgomery CTX set with modulus failure")
    }
    return montCtx
}

func IntToBN(sInt int) BigNum {
    bInt := big.NewInt(int64(sInt))
    return BigIntToBN(bInt)
}

func BigIntToBN(bInt *big.Int) BigNum {
    goIntAsBytes := bInt.Bytes()
    return BytesToBN(goIntAsBytes)
}

func BNToBigInt(bn BigNum) *big.Int {
    bytes := BNToBytes(bn)
    bInt := big.NewInt(0)
    bInt.SetBytes(bytes)
    return bInt
}

func BytesToBigInt(bytes []byte) *big.Int {
    bInt := big.NewInt(0)
    bInt.SetBytes(bytes)
    return bInt
}

func BytesToBN(bytes []byte) BigNum {
    cBytes := C.CBytes(bytes)
    defer C.free(cBytes)
    // cBN must be freed later by the calling function.
    var cBN BigNum = C.BN_bin2bn((*C.uint8_t)(cBytes), C.int(len(bytes)), GetBigNum())
    if unsafe.Pointer(cBN) == C.NULL {
        // Failure
        log.Fatal("Allocation failure")
    }
    return cBN
}

func BNToBytes(cBN BigNum) []byte {
    size := SizeOfBN(cBN)
    space := make([]byte, size)
    cSpace := C.CBytes(space)
    defer C.free(cSpace)

    written := C.BN_bn2bin(cBN, (*C.uint8_t)(cSpace))
    if int(written) != size {
        log.Fatal("Size of written doesn't equal size of bignum")
    }
    bytes := C.GoBytes(cSpace, C.int(size))
    return bytes
}

func SizeOfBN(cBN BigNum) int {
    // BN_num_bytes is a macro for this.
    return int((C.BN_num_bits(cBN)+7)/8)
}

func CompareBN(cBN1, cBN2 BigNum) int {
    return int(C.BN_cmp(cBN1, cBN2))
}

func MultiplyBN(cBN1, cBN2 BigNum) BigNum {
    // newBN must be freed later by the calling function.
    newBN := GetBigNum()
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := int(C.BN_mul(newBN, cBN1, cBN2, ctx))
    if result != 1 {
        // Failure
        log.Fatal("Multiplication failure")
    }
    return newBN
}

func AddBN(cBN1, cBN2 BigNum) BigNum {
    // newBN must be free later by the calling function.
    newBN := GetBigNum()
    result := C.BN_add(newBN, cBN1, cBN2)
    if result != 1 {
        log.Fatal("Addition failure")
    }
    return newBN
}

func SubBN(cBN1, cBN2 BigNum) BigNum {
    // newBN must be free later by the calling function.
    newBN := GetBigNum()
    result := C.BN_sub(newBN, cBN1, cBN2)
    if result != 1 {
        log.Fatal("Subtraction failure")
    }
    return newBN
}

func DivBN(numerator, divisor BigNum) (BigNum, BigNum) {
    quotient := GetBigNum()
    rem := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer C.BN_CTX_free(bnCtx)

    result := C.BN_div(quotient, rem, numerator, divisor, bnCtx)
    if result != 1 {
        log.Fatal("Division failure")
    }
    return quotient, rem
}

func ModBN(numerator, divisor BigNum) BigNum {
    bnCtx := C.BN_CTX_new()
    defer C.BN_CTX_free(bnCtx)
    // This is equivalent to C.BN_mod(bignum, hashDigest, orderMinusOne, bnCtx)
    // but it uses BN_div because it isn't a macro.
    quotient, rem := DivBN(numerator, divisor)
    defer FreeBigNum(quotient)
    return rem
}

func BNToDecStr(cBN BigNum) string {
    cString := C.BN_bn2dec(cBN)
    defer C.free(unsafe.Pointer(cString))

    return C.GoString(cString)
}

func RandRangeBN(max BigNum) BigNum {
    // randBN must be freed later by the calling function.
    randBN := GetBigNum()
    result := int(C.BN_rand_range(randBN, max))
    if result != 1 {
        // Failure
        log.Fatal("Random range returned failure")
    }
    return randBN
}
