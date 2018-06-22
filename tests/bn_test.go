package tests

import (
    "../libs/boringssl"
    "testing"
    "math/big"
    "math"
)

func TestIntToBigNum(t *testing.T) {
    bigboi1 := boringssl.IntToBN(10)
    defer boringssl.FreeBigNum(bigboi1)

    bigboi2 := boringssl.IntToBN(1000)
    defer boringssl.FreeBigNum(bigboi2)

    test1 := boringssl.CompareBN(bigboi1, bigboi2)
    if test1 >= 0 {
        t.Error("Got:",
            test1,
            "Expected: -1,",
            boringssl.BNToDecStr(bigboi1),
            boringssl.BNToDecStr(bigboi2))
    }

    bigboi3 := boringssl.IntToBN(10000)
    defer boringssl.FreeBigNum(bigboi3)

    test2 := boringssl.CompareBN(bigboi2, bigboi3)
    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            boringssl.BNToDecStr(bigboi2),
            boringssl.BNToDecStr(bigboi3))
    }

    test3 := boringssl.CompareBN(bigboi3, bigboi2)
    if test3 <= 0 {
        t.Error("Got:",
            test3,
            "Expected: 1,",
            boringssl.BNToDecStr(bigboi3),
            boringssl.BNToDecStr(bigboi2))
    }

    test4 := boringssl.CompareBN(bigboi3, bigboi1)
    if test4 <= 0 {
        t.Error("Got:",
            test4,
            "Expected: 1,",
            boringssl.BNToDecStr(bigboi3),
            boringssl.BNToDecStr(bigboi1))
    }
}

func TestBigIntToBigNumWithSmallInts(t *testing.T) {
    x := big.NewInt(10)
    y := big.NewInt(100)
    z := big.NewInt(1000)

    bigx := boringssl.BigIntToBN(x)
    bigy := boringssl.BigIntToBN(y)
    bigz := boringssl.BigIntToBN(z)

    defer boringssl.FreeBigNum(bigx)
    defer boringssl.FreeBigNum(bigy)
    defer boringssl.FreeBigNum(bigz)

    // Tests 1 and 2 should both be less than comparisons.
    test1 := boringssl.CompareBN(bigx, bigy)

    if test1 >= 0 {
        t.Error("Got:",
            test1,
            "Expected: -1,",
            boringssl.BNToDecStr(bigx),
            boringssl.BNToDecStr(bigy))
    }

    test2 := boringssl.CompareBN(bigy, bigz)

    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            boringssl.BNToDecStr(bigy),
            boringssl.BNToDecStr(bigz))
    }

    // Tests 3 and 4 should both be greater than comparisons.
    test3 := boringssl.CompareBN(bigy, bigx)

    if test3 <= 0 {
        t.Error("Got:",
            test3,
            "Expected: 1,",
            boringssl.BNToDecStr(bigy),
            boringssl.BNToDecStr(bigx))
    }

    test4 := boringssl.CompareBN(bigz, bigy)

    if test4 <= 0 {
        t.Error("Got:",
            test4,
            "Expected: 1,",
            boringssl.BNToDecStr(bigz),
            boringssl.BNToDecStr(bigy))
    }

    // Test 5 should be an equal to comparison.
    x2 := big.NewInt(10)
    bigx2 := boringssl.BigIntToBN(x2)
    defer boringssl.FreeBigNum(bigx2)

    test5 := boringssl.CompareBN(bigx, bigx2)
    if test5 != 0 {
        t.Error("Got:",
            test5,
            "Expected: 0,",
            boringssl.BNToDecStr(bigx),
            boringssl.BNToDecStr(bigx2))
    }
}

func TestBigIntToBigNumWithMul(t *testing.T) {
    x := big.NewInt(10)
    bigx := boringssl.BigIntToBN(x)
    defer boringssl.FreeBigNum(bigx)

    hugeboi := big.NewInt(math.MaxInt64)
    cHugeboi := boringssl.BigIntToBN(hugeboi)
    defer boringssl.FreeBigNum(cHugeboi)

    // Max int64 * 10
    cBiggerboi := boringssl.MultiplyBN(cHugeboi, bigx)
    defer boringssl.FreeBigNum(cBiggerboi)

    biggerboi := hugeboi.Mul(hugeboi, x)

    biggerboiConverted := boringssl.BigIntToBN(biggerboi)
    defer boringssl.FreeBigNum(biggerboiConverted)

    test1 := boringssl.CompareBN(cBiggerboi, biggerboiConverted)
    if test1 != 0 {
        t.Error("Got:",
            test1,
            "Expected: 0,",
            boringssl.BNToDecStr(cBiggerboi),
            boringssl.BNToDecStr(biggerboiConverted))
    }
}

func TestRandomRange(t *testing.T) {
    max := big.NewInt(math.MaxInt64)
    min := big.NewInt(0)

    cMax := boringssl.BigIntToBN(max)
    cMin := boringssl.BigIntToBN(min)
    defer boringssl.FreeBigNum(cMax)
    defer boringssl.FreeBigNum(cMin)

    cRand := boringssl.RandRangeBN(cMax)
    defer boringssl.FreeBigNum(cRand)

    test1 := boringssl.CompareBN(cMin, cRand)
    // The minimum is inclusive, so zero is possible to be equal to.
    if test1 > 0 {
        t.Error("Got:",
            test1,
            "Expected: -1 or 0,",
            boringssl.BNToDecStr(cMin),
            boringssl.BNToDecStr(cRand))
    }

    test2 := boringssl.CompareBN(cRand, cMax)
    // The maximum is exclusive, so max is impossible to be equal to.
    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            boringssl.BNToDecStr(cRand),
            boringssl.BNToDecStr(cMax))
    }
}
