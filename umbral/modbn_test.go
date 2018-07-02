package umbral

import (
    "testing"
)

func TestGenRandBN(t *testing.T) {
    curve := GetNewCurve(SECP256K1)

    one := IntToBN(1)
    defer FreeBigNum(one)

    for i := 0; i < 1000000; i++ {
        rand := GenRandBN(curve)

        // rand should always be between 1 inclusive and order exclusive
        min := CompareBN(one, rand.Bignum)
        max := CompareBN(rand.Bignum, curve.Order)

        if min > 0 || max >= 0 {
            t.Error("Got:",
                min, max,
                "Expecting: -1 or 0, -1",
                BNToDecStr(one),
                BNToDecStr(rand.Bignum),
                BNToDecStr(curve.Order))
        }
    }
}
