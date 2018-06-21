package boringssl

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR} -lcrypto

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
*/
import "C"
import (
    "unsafe"
    "math/big"
    "fmt"
)

func GetBigNum() *C.BIGNUM {
    var bigboi *C.BIGNUM = C.BN_new()
    return bigboi
}

func FreeBigNum(bigboi *C.BIGNUM) {
    C.BN_clear_free(bigboi)
}

func IntToBN(smallboi int) *C.BIGNUM {
    goBoi := big.NewInt(int64(smallboi))
    return BigIntToBN(goBoi)
}

func BigIntToBN(goInt *big.Int) *C.BIGNUM {
    goIntAsBytes := goInt.Bytes()
    cIntAsBytes := C.CBytes(goIntAsBytes)
    newBoi := GetBigNum()
    var bigboi = C.BN_bin2bn((*C.uint8_t)(cIntAsBytes),
        C.size_t(len(goIntAsBytes)),
        newBoi)
    if unsafe.Pointer(bigboi) != C.NULL {
        // Success
        return bigboi
    } else {
        // Failure
        fmt.Println("Allocation failure")
        return GetBigNum()
    }
}

func CompareBN(bigboi1, bigboi2 *C.BIGNUM) int {
    cint := C.BN_cmp(bigboi1, bigboi2)
    return int(cint)
}

func MultiplyBN(bigboi1, bigboi2 *C.BIGNUM) *C.BIGNUM {
    newBoi := GetBigNum()
    ctx := C.BN_CTX_new()
    result := int(C.BN_mul(newBoi, bigboi1, bigboi2, ctx))
    if result == 1 {
        // Success
        return newBoi
    } else {
        // Failure
        fmt.Println("Multiplication failure")
        return GetBigNum()
    }
}

func BNToDec(bigboi *C.BIGNUM) string {
    cString := C.BN_bn2dec(bigboi)
    goString := C.GoString(cString)
    return goString
}
