package umbral

// #include "shim.h"
import "C"
import (
    "unsafe"
    "golang.org/x/crypto/blake2b"
    "errors"
)

/*
Represents a BoringSSL Bignum modulo the order of a curve. Some of these
operations will only work with prime numbers
*/

type ModBigNum struct {
   Bignum BigNum
   Curve Curve
}

func GetNewModBN(cNum BigNum, curve Curve) (ModBigNum, error) {
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
    Returns a CurveBN object with a cryptographically secure OpenSSL BIGNUM
    based on the given curve.
    */

    // newRandBN needs to be from 1 inclusive to curve exclusive
    newRandBN := RandRangeBN(curve.Order)

    if !BNIsWithinOrder(newRandBN, curve) {
        FreeBigNum(newRandBN)
        return GenRandModBN(curve)
    }
    return ModBigNum{Bignum: newRandBN, Curve: curve}, nil
}

func Int2ModBN(num int, curve Curve) (ModBigNum, error) {
    newBN := IntToBN(num)

    return ModBigNum{Bignum: newBN, Curve: curve}, nil
}

func Hash2ModBN(bytes []byte, curve Curve) (ModBigNum, error) {
    if len(bytes) == 0 {
        return ModBigNum{}, errors.New("No bytes to hash")
    }
    blake2b, err := blake2b.New(64, bytes)
    if err != nil {
        return ModBigNum{}, err
    }
    var hashContainer []byte
    blake2b.Sum(hashContainer)
    hashDigest := BytesToBN(hashContainer)

    oneBN := IntToBN(1)
    defer FreeBigNum(oneBN)

    orderMinusOne := SubBN(curve.Order, oneBN)
    defer FreeBigNum(orderMinusOne)

    moddedResult := ModBN(hashDigest, orderMinusOne)
    defer FreeBigNum(moddedResult)

    bignum := AddBN(moddedResult, oneBN)

    return ModBigNum{Bignum: bignum, Curve: curve}, nil
}

func Bytes2ModBN(data []byte, curve Curve) (ModBigNum, error) {
    if len(data) == 0 {
        return ModBigNum{}, errors.New("No bytes failure")
    }

    bignum := BytesToBN(data)
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

func (m *ModBigNum) Pow(other ModBigNum) {
    power := ModExpBN(m.Bignum, other.Bignum, m.Curve.Order)
    FreeBigNum(m.Bignum)

    m.Bignum = power
}

func (m *ModBigNum) Mul(other ModBigNum) {
    product := ModMulBN(m.Bignum, other.Bignum, m.Curve.Order)
    FreeBigNum(m.Bignum)

    m.Bignum = product
}

func (m *ModBigNum) Div(other ModBigNum) {
    tmpBN := ModInverseBN(other.Bignum, m.Curve.Order)
    defer FreeBigNum(tmpBN)

    product := ModMulBN(m.Bignum, tmpBN, m.Curve.Order)

    FreeBigNum(m.Bignum)

    m.Bignum = product
}

func (m *ModBigNum) Add(other ModBigNum) {
    sum := ModAddBN(m.Bignum, other.Bignum, m.Curve.Order)

    FreeBigNum(m.Bignum)

    m.Bignum = sum
}

func (m *ModBigNum) Sub(other ModBigNum) {
    sub := ModSubBN(m.Bignum, other.Bignum, m.Curve.Order)

    FreeBigNum(m.Bignum)

    m.Bignum = sub
}

func (m *ModBigNum) Inverse() {
    inverse := ModInverseBN(m.Bignum, m.Curve.Order)

    FreeBigNum(m.Bignum)

    m.Bignum = inverse
}

func (m *ModBigNum) Mod(other ModBigNum) {
    rem := NNModBN(m.Bignum, other.Bignum)

    FreeBigNum(m.Bignum)

    m.Bignum = rem
}
