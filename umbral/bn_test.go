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

import (
    "testing"
    "math/big"
    "math"
)

func TestIntToBigNum(t *testing.T) {
    bigboi1 := IntToBN(10)
    defer FreeBigNum(bigboi1)

    bigboi2 := IntToBN(1000)
    defer FreeBigNum(bigboi2)

    test1 := CompareBN(bigboi1, bigboi2)
    if test1 >= 0 {
        t.Error("Got:",
            test1,
            "Expected: -1,",
            BNToDecStr(bigboi1),
            BNToDecStr(bigboi2))
    }

    bigboi3 := IntToBN(10000)
    defer FreeBigNum(bigboi3)

    test2 := CompareBN(bigboi2, bigboi3)
    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            BNToDecStr(bigboi2),
            BNToDecStr(bigboi3))
    }

    test3 := CompareBN(bigboi3, bigboi2)
    if test3 <= 0 {
        t.Error("Got:",
            test3,
            "Expected: 1,",
            BNToDecStr(bigboi3),
            BNToDecStr(bigboi2))
    }

    test4 := CompareBN(bigboi3, bigboi1)
    if test4 <= 0 {
        t.Error("Got:",
            test4,
            "Expected: 1,",
            BNToDecStr(bigboi3),
            BNToDecStr(bigboi1))
    }
}

func TestBigIntToBigNumWithSmallInts(t *testing.T) {
    x := big.NewInt(10)
    y := big.NewInt(100)
    z := big.NewInt(1000)

    bigx := BigIntToBN(x)
    bigy := BigIntToBN(y)
    bigz := BigIntToBN(z)

    defer FreeBigNum(bigx)
    defer FreeBigNum(bigy)
    defer FreeBigNum(bigz)

    // Tests 1 and 2 should both be less than comparisons.
    test1 := CompareBN(bigx, bigy)

    if test1 >= 0 {
        t.Error("Got:",
            test1,
            "Expected: -1,",
            BNToDecStr(bigx),
            BNToDecStr(bigy))
    }

    test2 := CompareBN(bigy, bigz)

    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            BNToDecStr(bigy),
            BNToDecStr(bigz))
    }

    // Tests 3 and 4 should both be greater than comparisons.
    test3 := CompareBN(bigy, bigx)

    if test3 <= 0 {
        t.Error("Got:",
            test3,
            "Expected: 1,",
            BNToDecStr(bigy),
            BNToDecStr(bigx))
    }

    test4 := CompareBN(bigz, bigy)

    if test4 <= 0 {
        t.Error("Got:",
            test4,
            "Expected: 1,",
            BNToDecStr(bigz),
            BNToDecStr(bigy))
    }

    // Test 5 should be an equal to comparison.
    x2 := big.NewInt(10)
    bigx2 := BigIntToBN(x2)
    defer FreeBigNum(bigx2)

    test5 := CompareBN(bigx, bigx2)
    if test5 != 0 {
        t.Error("Got:",
            test5,
            "Expected: 0,",
            BNToDecStr(bigx),
            BNToDecStr(bigx2))
    }
}

func TestBigIntToBigNumWithMul(t *testing.T) {
    x := big.NewInt(10)
    bigx := BigIntToBN(x)
    defer FreeBigNum(bigx)

    hugeboi := big.NewInt(math.MaxInt64)
    cHugeboi := BigIntToBN(hugeboi)
    defer FreeBigNum(cHugeboi)

    // Max int64 * 10
    cBiggerboi := MultiplyBN(cHugeboi, bigx)
    defer FreeBigNum(cBiggerboi)

    biggerboi := hugeboi.Mul(hugeboi, x)

    biggerboiConverted := BigIntToBN(biggerboi)
    defer FreeBigNum(biggerboiConverted)

    test1 := CompareBN(cBiggerboi, biggerboiConverted)
    if test1 != 0 {
        t.Error("Got:",
            test1,
            "Expected: 0,",
            BNToDecStr(cBiggerboi),
            BNToDecStr(biggerboiConverted))
    }
}

func TestRandomRange(t *testing.T) {
    max := big.NewInt(math.MaxInt64)
    min := big.NewInt(0)

    cMax := BigIntToBN(max)
    cMin := BigIntToBN(min)
    defer FreeBigNum(cMax)
    defer FreeBigNum(cMin)

    cRand := RandRangeBN(cMax)
    defer FreeBigNum(cRand)

    test1 := CompareBN(cMin, cRand)
    // The minimum is inclusive, so zero is possible to be equal to.
    if test1 > 0 {
        t.Error("Got:",
            test1,
            "Expected: -1 or 0,",
            BNToDecStr(cMin),
            BNToDecStr(cRand))
    }

    test2 := CompareBN(cRand, cMax)
    // The maximum is exclusive, so max is impossible to be equal to.
    if test2 >= 0 {
        t.Error("Got:",
            test2,
            "Expected: -1,",
            BNToDecStr(cRand),
            BNToDecStr(cMax))
    }
}
