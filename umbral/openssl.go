package umbral

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
    // generator must be freed later by the calling function.
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

func GetNewECPoint(curve Curve) ECPoint {
    // newPoint must be freed later by the calling function.
    newPoint := C.EC_POINT_new(curve.Group)
    if unsafe.Pointer(newPoint) == C.NULL {
        // Failure
        log.Fatal("New EC Point failure")
    }
    return newPoint
}

func GetECPointFromAffine(affineX, affineY BigNum, curve Curve) ECPoint {
    // newPoint must be freed later by the calling function.
    newPoint := GetNewECPoint(curve)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_set_affine_coordinates_GFp(
            curve.Group, newPoint, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        log.Fatal("EC Point lookup failure")
    }
    return newPoint
}

func GetAffineCoordsFromECPoint(point ECPoint, curve Curve) (BigNum, BigNum) {
    // affineX and affineY must be freed later by the calling function.
    affineX := GetBigNum()
    affineY := GetBigNum()

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_get_affine_coordinates_GFp(
            curve.Group, point, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        log.Fatal("Affine lookup failure")
    }
    return affineX, affineY
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

func IntToBN(sInt int) *C.BIGNUM {
    bInt := big.NewInt(int64(sInt))
    return BigIntToBN(bInt)
}

func BigIntToBN(bInt *big.Int) *C.BIGNUM {
    goIntAsBytes := bInt.Bytes()
    return BytesToBN(goIntAsBytes)
}

func BytesToBN(bytes []byte) *C.BIGNUM {
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

func BNToBytes(cBN *C.BIGNUM) []byte {
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

func CompareBN(cBN1, cBN2 *C.BIGNUM) int {
    return int(C.BN_cmp(cBN1, cBN2))
}

func MultiplyBN(cBN1, cBN2 *C.BIGNUM) *C.BIGNUM {
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

func AddBN(cBN1, cBN2 *C.BIGNUM) *C.BIGNUM {
    // newBN must be free later by the calling function.
    newBN := GetBigNum()
    result := C.BN_add(newBN, cBN1, cBN2)
    if result != 1 {
        log.Fatal("Addition failure")
    }
    return newBN
}

func SubBN(cBN1, cBN2 *C.BIGNUM) *C.BIGNUM {
    // newBN must be free later by the calling function.
    newBN := GetBigNum()
    result := C.BN_sub(newBN, cBN1, cBN2)
    if result != 1 {
        log.Fatal("Subtraction failure")
    }
    return newBN
}

func DivBN(numerator, divisor *C.BIGNUM) (*C.BIGNUM, *C.BIGNUM) {
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

func ModBN(numerator, divisor *C.BIGNUM) *C.BIGNUM {
    bnCtx := C.BN_CTX_new()
    defer C.BN_CTX_free(bnCtx)
    // This is equivalent to C.BN_mod(bignum, hashDigest, orderMinusOne, bnCtx)
    // but it uses BN_div because it isn't a macro.
    quotient, rem := DivBN(numerator, divisor)
    defer FreeBigNum(quotient)
    return rem
}

func ModExpBN(cBN1, cBN2, mod *C.BIGNUM) *C.BIGNUM {
    /*
    Performs a BN_mod_exp on two BIGNUMS.
    WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
    */
    power := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    bnMontCtx := TmpBNMontCTX(mod)
    result := C.BN_mod_exp_mont_consttime(power,
        cBN1, cBN2, mod, bnCtx, bnMontCtx)

    if result != 1 {
        log.Fatal("BN_mod_exp failure")
    }

    return power
}

func ModMulBN(cBN1, cBN2, mod *C.BIGNUM) *C.BIGNUM {
    /*
    Performs a BN_mod_mul between two BIGNUMS.
    */
    product := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_mul(product, cBN1, cBN2, mod, bnCtx)
    if result != 1 {
        log.Fatal("BN_mod_mul failure")
    }
    return product
}

func ModInverseBN(cBN, mod *C.BIGNUM) *C.BIGNUM {
    product := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    // NULL is used in place of out_no_inverse because
    // the inverse should always exist for SECP256K1.
    result := C.BN_mod_inverse(product, cBN, mod, bnCtx)

    if unsafe.Pointer(result) == C.NULL {
        log.Fatal("BN_mod_inverse failure")
    }

    return product
}

func ModAddBN(cBN1, cBN2, mod *C.BIGNUM) *C.BIGNUM {
    sum := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_add(sum, cBN1, cBN2, mod, bnCtx)
    if result != 1 {
        log.Fatal("BN_mod_add failure")
    }

    return sum
}

func ModSubBN(cBN1, cBN2, mod *C.BIGNUM) *C.BIGNUM {
    sub := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_mod_sub(sub, cBN1, cBN2, mod, bnCtx)
    if result != 1 {
        log.Fatal("BN_mod_sub failure")
    }

    return sub
}

func NNModBN(cBN1, cBN2 *C.BIGNUM) *C.BIGNUM {
    rem := GetBigNum()

    bnCtx := C.BN_CTX_new()
    defer FreeBNCTX(bnCtx)

    result := C.BN_nnmod(rem, cBN1, cBN2, bnCtx)
    if result != 1 {
        log.Fatal("BN_mod_sub failure")
    }

    return rem
}

func BNToDecStr(cBN *C.BIGNUM) string {
    cString := C.BN_bn2dec(cBN)
    defer C.free(unsafe.Pointer(cString))

    return C.GoString(cString)
}

func RandRangeBN(max *C.BIGNUM) *C.BIGNUM {
    // randBN must be freed later by the calling function.
    randBN := GetBigNum()
    result := int(C.BN_rand_range(randBN, max))
    if result != 1 {
        // Failure
        log.Fatal("Random range returned failure")
    }
    return randBN
}
