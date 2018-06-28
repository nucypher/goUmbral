package umbral

// #include "shim.h"
import "C"
import (
    "unsafe"
    "math/big"
    "log"
)

// secp256k1 is the constant curve nid 714
const SECP256K1 = 714
var globalGroup ECGroup
var globalOrder ECOrder

type BigNum *C.BIGNUM
type BNCtx *C.BN_CTX
type BNMontCtx *C.BN_MONT_CTX
type ECGroup *C.EC_GROUP
type ECOrder *C.BIGNUM
type ECPoint *C.EC_POINT

func GetBigNum() *C.BIGNUM {
    // bNum must be freed later by the calling function.
    var bNum *C.BIGNUM = C.BN_new()
    return bNum
}

/*
func FindECGroups() {
    for i := 0; i < 1000; i++ {
        ecGroup := C.EC_GROUP_new_by_curve_name(C.int(i))
        if unsafe.Pointer(ecGroup) != C.NULL {
            // Failure
            log.Fatal("Got:", i)
        }
    }
}
*/

func SetECGroup() {
    if unsafe.Pointer(globalGroup) == C.NULL {
        globalGroup = C.EC_GROUP_new_by_curve_name(C.int(415))
        /*
        if unsafe.Pointer(globalGroup) == C.NULL {
            // Failure
            log.Fatal("Curve group lookup failed")
        }
        */
    }
}

func SetECOrder() {
    if unsafe.Pointer(globalOrder) == C.NULL {
        ecOrder := GetBigNum()
        var bnCtx *C.BN_CTX = C.BN_CTX_new()
        defer FreeBNCTX(bnCtx)
        if unsafe.Pointer(globalGroup) == C.NULL {
            SetECGroup()
        }
        result := int(C.EC_GROUP_get_order(globalGroup, ecOrder, bnCtx))
        if result != 1 {
            // Failure
            log.Fatal("Curve order lookup failed")
        }
        globalOrder = ecOrder
    }
}

func GetECGroup() *C.EC_GROUP {
    if unsafe.Pointer(globalGroup) == C.NULL {
        SetECGroup()
    }
    return globalGroup
}

func GetECOrder() *C.BIGNUM {
    if unsafe.Pointer(globalOrder) == C.NULL {
        SetECOrder()
    }
    return globalOrder
}

func GetECGroupByCurveNid(curveNid int) *C.EC_GROUP {
    // curve must be freed later by the calling function.
    var curve *C.EC_GROUP = C.EC_GROUP_new_by_curve_name(C.int(curveNid))
    if unsafe.Pointer(curve) == C.NULL {
        // Failure
        log.Fatal("Curve group lookup failed")
    }
    return curve
}

func GetECOrderByCurveNid(curveNid int) *C.BIGNUM {
    var ecGroup *C.EC_GROUP = GetECGroupByCurveNid(curveNid)
    defer FreeECGroup(ecGroup)

    // ecOrder must be freed later by the calling function.
    var ecOrder *C.BIGNUM = GetBigNum()

    var ctx *C.BN_CTX = C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := int(C.EC_GROUP_get_order(ecGroup, ecOrder, ctx))
    if result != 1 {
        // Failure
        log.Fatal("Curve order lookup failed")
    }
    return ecOrder
}

func GetECGeneratorByCurveNid(nid int) *C.EC_POINT {
    var ecGroup *C.EC_GROUP = GetECGroupByCurveNid(nid)

    // generator must be freed later by the calling function.
    var generator *C.EC_POINT = C.EC_GROUP_get0_generator(ecGroup)

    if unsafe.Pointer(generator) == C.NULL {
        // Failure
        log.Fatal("Generator failure")
    }
    return generator
}

func FreeBigNum(bigboi *C.BIGNUM) {
    C.BN_clear_free(bigboi)
}

func FreeECPoint(ecPoint *C.EC_POINT) {
    C.EC_POINT_clear_free(ecPoint)
}

func FreeECGroup(ecGroup *C.EC_GROUP) {
    C.EC_GROUP_free(ecGroup)
}

func FreeBNCTX(ctx *C.BN_CTX) {
    C.BN_CTX_free(ctx)
}

func FreeBNMontCTX(montCtx *C.BN_MONT_CTX) {
    C.BN_MONT_CTX_free(montCtx)
}

func GetECGroupDegree(ecGroup *C.EC_GROUP) uint {
    return uint(C.EC_GROUP_get_degree(ecGroup))
}

func BNIsWithinOrder(checkBN *C.BIGNUM, nid int) bool {
    ecOrder := GetECOrderByCurveNid(nid)
    defer FreeBigNum(ecOrder)

    zero := IntToBN(0)
    defer FreeBigNum(zero)

    checkSign := C.BN_cmp(checkBN, zero)
    rangeCheck := C.BN_cmp(checkBN, ecOrder)

    return checkSign == 1 && rangeCheck == -1
}

func GetNewECPoint(ecGroup *C.EC_GROUP, curveNid int) *C.EC_POINT {
    if (unsafe.Pointer(ecGroup) == C.NULL) {
        ecGroup = GetECGroupByCurveNid(curveNid)
    }
    // newPoint must be freed later by the calling function.
    newPoint := C.EC_POINT_new(ecGroup)
    if unsafe.Pointer(newPoint) == C.NULL {
        // Failure
        log.Fatal("New EC Point failure")
    }
    return newPoint
}

func GetECPointFromAffine(affineX, affineY *C.BIGNUM, ecGroup *C.EC_GROUP, curveNid int) *C.EC_POINT {
    if (unsafe.Pointer(ecGroup) == C.NULL) {
        ecGroup = GetECGroupByCurveNid(curveNid)
    }

    // newPoint must be freed later by the calling function.
    newPoint := GetNewECPoint(ecGroup, curveNid)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_set_affine_coordinates_GFp(
            ecGroup, newPoint, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        log.Fatal("EC Point lookup failure")
    }
    return newPoint
}

func GetAffineCoordsFromECPoint(ecPoint *C.EC_POINT, ecGroup *C.EC_GROUP, curveNid int) (*C.BIGNUM, *C.BIGNUM) {
    if (unsafe.Pointer(ecGroup) == C.NULL) {
        ecGroup = GetECGroupByCurveNid(curveNid)
    }

    // affineX and affineY must be freed later by the calling function.
    affineX := GetBigNum()
    affineY := GetBigNum()

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_get_affine_coordinates_GFp(
            ecGroup, ecPoint, affineX, affineY, ctx)
    if result != 1 {
        // Failure
        log.Fatal("Affine lookup failure")
    }
    return affineX, affineY
}

func TmpBNMontCTX(modulus *C.BIGNUM) *C.BN_MONT_CTX {
    // montCtx must be freed later by the calling function.
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    montCtx := C.BN_MONT_CTX_new_consttime(modulus, ctx)
    if unsafe.Pointer(montCtx) == C.NULL {
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
    var cBN *C.BIGNUM = C.BN_bin2bn((*C.uint8_t)(cBytes), C.size_t(len(bytes)), GetBigNum())
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

func SizeOfBN(cBN *C.BIGNUM) int {
    return int(C.BN_num_bytes(cBN))
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
    defer FreeBigNum(power)

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
    result := C.BN_mod_inverse_blinded(product, (*C.int)(C.NULL), cBN, TmpBNMontCTX(mod), bnCtx)

    if result != 1 {
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

func RandRangeExBN(min uint32, max *C.BIGNUM) *C.BIGNUM {
    // randBN must be free later by the calling function.
    randBN := GetBigNum()
    result := int(C.BN_rand_range_ex(randBN, C.size_t(min), max))
    if result != 1 {
        // Failure
        log.Fatal("Random range ex returned failure")
    }
    return randBN
}
