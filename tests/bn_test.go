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
        t.Error("Got:", test1, "Expected: -1, 10 to be less than 1000")
    }

    bigboi3 := boringssl.IntToBN(10000)
    defer boringssl.FreeBigNum(bigboi3)

    test2 := boringssl.CompareBN(bigboi2, bigboi3)
    if test2 >= 0 {
        t.Error("Got:", test2, "Expected: -1, 1000 to be less than 10000")
    }

    test3 := boringssl.CompareBN(bigboi3, bigboi2)
    if test3 <= 0 {
        t.Error("Got:", test3, "Expected: 1, 10000 to be more than 1000")
    }

    test4 := boringssl.CompareBN(bigboi3, bigboi1)
    if test4 <= 0 {
        t.Error("Got:", test4, "Expected: 1, 10000 to be more than 10")
    }
}

func TestBigIntToBigNum(t *testing.T) {
    x := big.NewInt(10)
    y := big.NewInt(100)
    z := big.NewInt(1000)

    bigx := boringssl.BigIntToBN(x)
    bigy := boringssl.BigIntToBN(y)
    bigz := boringssl.BigIntToBN(z)

    for i := int64(0); i < 100000; i++ {
        sizeTest := big.NewInt(i)

        bigTest := boringssl.BigIntToBN(sizeTest)

        cString := boringssl.BNToDec(bigTest)
        goString := sizeTest.String()

        if cString != goString {
            t.Error("Comparison desync:", goString, cString)
        }
    }

    defer boringssl.FreeBigNum(bigx)
    defer boringssl.FreeBigNum(bigy)
    defer boringssl.FreeBigNum(bigz)

    // Tests 1 and 2 should both be less than comparisons.
    test1 := boringssl.CompareBN(bigx, bigy)

    if test1 >= 0 {
        t.Error("Got:", test1, "Expected: -1, 10 to be less than 100")
    }

    test2 := boringssl.CompareBN(bigy, bigz)

    if test2 >= 0 {
        t.Error("Got:", test2, "Expected: -1, 100 to be less than 1000")
    }

    // Tests 3 and 4 should both be greater than comparisons.
    test3 := boringssl.CompareBN(bigy, bigx)

    if test3 <= 0 {
        t.Error("Got:", test3, "Expected: 1, 100 to be more than 10")
    }

    test4 := boringssl.CompareBN(bigz, bigy)

    if test4 <= 0 {
        t.Error("Got:", test4, "Expected: 1, 1000 to be more than 100")
    }

    // Test 5 should be an equal to comparison.
    x2 := big.NewInt(10)
    bigx2 := boringssl.BigIntToBN(x2)
    defer boringssl.FreeBigNum(bigx2)

    test5 := boringssl.CompareBN(bigx, bigx2)
    if test5 != 0 {
        t.Error("Got:", test5, "Expected: 0, 10 to be equal to 10")
    }

    // LARGER NUMBERS
    hugeboi := big.NewInt(math.MaxInt64)
    cHugeboi := boringssl.BigIntToBN(hugeboi)
    t.Log(boringssl.BNToDec(cHugeboi), hugeboi.String())
    defer boringssl.FreeBigNum(cHugeboi)

    // Max int64 * 10
    cBiggerboi := boringssl.MultiplyBN(cHugeboi, bigx)
    defer boringssl.FreeBigNum(cBiggerboi)

    biggerboi := hugeboi.Mul(hugeboi, x)

    biggerboiConverted := boringssl.BigIntToBN(biggerboi)
    defer boringssl.FreeBigNum(biggerboiConverted)

    test6 := boringssl.CompareBN(cBiggerboi, biggerboiConverted)
    if test6 != 0 {
        t.Error("Got:", test6, "Expected: 0,", boringssl.BNToDec(cBiggerboi), boringssl.BNToDec(biggerboiConverted))
    }
}
