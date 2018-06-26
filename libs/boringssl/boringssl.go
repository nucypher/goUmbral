package boringssl

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR} -lcrypto

#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
*/
import "C"
import (
    "unsafe"
    "math/big"
    "log"
)

// secp256k1 is the constant curve nid 714
const globalNid = 714
var globalGroup *C.EC_GROUP

func GetBigNum() *C.BIGNUM {
    // bNum must be freed later by the calling function.
    var bNum *C.BIGNUM = C.BN_new()
    return bNum
}

func SetECGroupByCurveNid() {
    if unsafe.Pointer(globalGroup) == C.NULL {
        globalGroup = C.EC_GROUP_new_by_curve_name(C.int(globalNid))
        if unsafe.Pointer(globalGroup) == C.NULL {
            // Failure
            log.Fatal("Curve group lookup failed")
        }
    }
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

func GetECOrderByGlobalGroup() *C.BIGNUM {
    // ecOrder must be freed later by the calling function.
    var ecOrder *C.BIGNUM = GetBigNum()

    var ctx *C.BN_CTX = C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := int(C.EC_GROUP_get_order(globalGroup, ecOrder, ctx))
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
    montCtx := C.BN_MONT_CTX_new()
    if unsafe.Pointer(montCtx) == C.NULL {
        log.Fatal("New Montgomery CTX failure")
    }
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.BN_MONT_CTX_set(montCtx, modulus, ctx)
    if result != 1 {
        log.Fatal("Montgomery CTX set with modulus failure")
    }
    return montCtx
}

func IntToBN(sInt int) *C.BIGNUM {
    bInt := big.NewInt(int64(sInt))
    return BigIntToBN(bInt)
}

func BigIntToBN(bInt *big.Int) *C.BIGNUM {
    goIntAsBytes := bInt.Bytes()

    cIntAsBytes := C.CBytes(goIntAsBytes)
    defer C.free(cIntAsBytes)

    // cBN must be freed later by the calling function.
    var cBN *C.BIGNUM = C.BN_bin2bn((*C.uint8_t)(cIntAsBytes),
        C.size_t(len(goIntAsBytes)),
        GetBigNum())
    if unsafe.Pointer(cBN) == C.NULL {
        // Failure
        log.Fatal("Allocation failure")
    }
    return cBN
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
