package umbral

import (
    "../libs/boringssl"
    "golang.org/x/crypto/blake2b"
    "log"
)

/*
Represents a BoringSSL Bignum modulo the order of a curve. Some of these
operations will only work with prime numbers
*/

// TODO: Cleanup this place for single curve support.
type ModBigNum struct {
   bignum boringssl.BigNum
   curveNid int
   group boringssl.ECGroup
   order boringssl.BigNum
}

func GetNewModBN(cNum boringssl.BigNum, nid int, ecGroup boringssl.ECGroup, ecOrder boringssl.BigNum) ModBigNum {
    if nid != 0 {
        if !boringssl.BNIsWithinOrder(cNum, nid) {
            log.Fatal("The provided BIGNUM is not on the provided curve.")
        }
    }
    return ModBigNum{bignum: cNum,
        curveNid: nid, group: ecGroup, order: ecOrder}
}

func GenRandBN() ModBigNum {
    /*
    Returns a CurveBN object with a cryptographically secure OpenSSL BIGNUM
    based on the given curve.
    */
    ecGroup := boringssl.GetECGroup()
    ecOrder := boringssl.GetECOrder()

    // newRandBN needs to be from 1 inclusive to curve exclusive
    newRandBN := boringssl.RandRangeExBN(1, ecOrder)

    if !boringssl.BNIsWithinOrder(newRandBN, boringssl.SECP256K1) {
        return GenRandBN()
    }
    return ModBigNum{bignum: newRandBN, curveNid: boringssl.SECP256K1,
        group: ecGroup, order: ecOrder}
}

func FromInt(num int) ModBigNum {
    ecGroup := boringssl.GetECGroup()
    ecOrder := boringssl.GetECOrder()

    newBN := boringssl.IntToBN(num)

    return ModBigNum{bignum: newBN, curveNid: boringssl.SECP256K1,
        group: ecGroup, order: ecOrder}
}

func Hash(bytes []byte) ModBigNum {
    if len(bytes) == 0 {
        log.Fatal("No bytes to hash")
    }
    blake2b, err := blake2b.New(64, bytes)
    if err != nil {
        log.Fatal(err)
    }
    var hashContainer []byte
    blake2b.Sum(hashContainer)
    hashDigest := boringssl.BytesToBN(hashContainer)

    oneBN := boringssl.IntToBN(1)
    defer boringssl.FreeBigNum(oneBN)

    orderMinusOne := boringssl.SubBN(boringssl.GetECOrder(), oneBN)
    defer boringssl.FreeBigNum(orderMinusOne)

    moddedResult := boringssl.ModBN(hashDigest, orderMinusOne)
    defer boringssl.FreeBigNum(moddedResult)

    bignum := boringssl.AddBN(moddedResult, oneBN)

    return ModBigNum{bignum: bignum, curveNid: boringssl.SECP256K1,
        group: boringssl.GetECGroup(), order: boringssl.GetECOrder()}
}

func FromBytes(data []byte) ModBigNum {
    if len(data) == 0 {
        log.Fatal("No bytes failure")
    }
    bignum := boringssl.BytesToBN(data)
    return ModBigNum{bignum: bignum, curveNid: boringssl.SECP256K1,
        group: boringssl.GetECGroup(), order: boringssl.GetECOrder()}
}

func (m *ModBigNum) ToBytes() []byte {
    return boringssl.BNToBytes(m.bignum)
}

func (m *ModBigNum) Equals(other *ModBigNum) int {
    // -1 less than, 0 is equal to, 1 is greater than
    return boringssl.CompareBN(m.bignum, other.bignum)
}

func (m *ModBigNum) Pow(other *ModBigNum) ModBigNum {
    power := boringssl.ModExpBN(m.bignum, other.bignum, m.order)

    return ModBigNum{bignum: power, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Mul(other *ModBigNum) ModBigNum {
    product := boringssl.ModMulBN(m.bignum, other.bignum, m.order)

    return ModBigNum{bignum: product, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Div(other *ModBigNum) ModBigNum {
    tmpBN := boringssl.ModInverseBN(other.bignum, m.order)
    product := boringssl.ModMulBN(m.bignum, tmpBN, m.order)

    return ModBigNum{bignum: product, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Add(other *ModBigNum) ModBigNum {
    sum := boringssl.ModAddBN(m.bignum, other.bignum, m.order)

    return ModBigNum{bignum: sum, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Sub(other *ModBigNum) ModBigNum {
    sub := boringssl.ModSubBN(m.bignum, other.bignum, m.order)

    return ModBigNum{bignum: sub, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Inverse() ModBigNum {
    inverse := boringssl.ModInverseBN(m.bignum, m.order)

    return ModBigNum{bignum: inverse, curveNid: m.curveNid,
        group: m.group, order: m.order}
}

func (m *ModBigNum) Mod(other *ModBigNum) ModBigNum {
    rem := boringssl.NNModBN(m.bignum, other.bignum)

    return ModBigNum{bignum: rem, curveNid: m.curveNid,
        group: m.group, order: m.order}
}
