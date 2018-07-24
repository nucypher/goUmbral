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
    "golang.org/x/crypto/blake2b"
    "math/big"
    "encoding/binary"
    "testing"
    "math"
)

func TestNewModBN(t *testing.T) {
    t.Run("bn=5", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        bn := IntToBN(5)
        // Should succeed.
        modbn, err := GetNewModBN(bn, curve)
        if err != nil {
            t.Error(err)
        }
        modbn.Free()
    })
    t.Run("bn=-10", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        // IntToBN is unsigned.
        onebn := IntToBN(1)
        defer FreeBigNum(onebn)

        tenbn := IntToBN(10)
        defer FreeBigNum(tenbn)

        negbn := SubBN(onebn, tenbn)

        // Should fail.
        modbn, err := GetNewModBN(negbn, curve)
        if err == nil {
            t.Error("A negative bignum should not be within the order of the curve")
        }
        modbn.Free()
    })
}

func TestGenRandBN(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    one := IntToBN(1)
    defer FreeBigNum(one)

    for i := 0; i < 1000; i++ {
        rand, err := GenRandModBN(curve)
        if err != nil {
            t.Error(err)
        }
        defer rand.Free()

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

func TestInt2ModBN(t *testing.T) {
    curve, err := GetNewCurve(SECP384R1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn, err := Int2ModBN(10, curve)
    if err != nil {
        t.Error(err)
    }
    modbn.Free()
}

func TestHash2BN(t *testing.T) {
    t.Run("bs=4, bn=999111777", func(t *testing.T) {
        // Choose a number.
        bs := make([]byte, 4)
        binary.BigEndian.PutUint32(bs, 999111777)

        // Get the curve.
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        // Convert to BN with Hash2BN.
        bn, err := Hash2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }
        defer bn.Free()

        // Hash the number with blake2b and convert to Go big.Int.
        hash := blake2b.Sum512(bs)
        goBN := big.NewInt(0)
        goBN.SetBytes(hash[:])

        // Convert the order to Go big.Int.
        goOrder := big.NewInt(0)
        goOrder.SetBytes(BNToBytes(curve.Order))

        // Subtract one from the order of the curve.
        goOrder.Sub(goOrder, big.NewInt(1))

        // Mod goBN by (order - 1) and set goBN.
        goBN.Mod(goBN, goOrder)

        // Add one
        goBN.Add(goBN, big.NewInt(1))

        newBN := BigIntToBN(goBN)
        defer FreeBigNum(newBN)

        // newBN and bn should be equal
        result := CompareBN(newBN, bn.Bignum)

        if result != 0 {
            t.Error("The two hashed and modded bn's were not the same:", result)
        }
    })

    t.Run("bs=0", func(t *testing.T) {
        // Test an empty byte array.
        var bs []byte
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        modbn, err := Hash2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }
        modbn.Free()
    })

    t.Run("bs>64", func(t *testing.T) {
        // Should support byte arrays up to 4GB.
        // bs := make([]byte, math.MaxInt32) - This would test a byte array that is size 2.1 billion, or 2.1GB.
        bs := make([]byte, math.MaxInt16)
        bs[127] = byte(42)
        bs[100] = byte(52)
        curve, err := GetNewCurve(SECP384R1)
        if err != nil {
            t.Error(err)
        }
        curve.Free()

        modbn, err := Hash2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }
        modbn.Free()
    })
}

func TestBytesToModBN(t *testing.T) {
    t.Run("normal", func(t *testing.T) {
        bs := make([]byte, 4)
        binary.BigEndian.PutUint32(bs, 999111777)

        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        modbn, err := Bytes2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }
        modbn.Free()
    })

    t.Run("empty", func(t *testing.T) {
        var bs []byte
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        modbn, err := Bytes2ModBN(bs, curve)
        if err == nil {
            t.Error("An empty byte array returned a valid bignum.")
        }
        modbn.Free()
    })
}

func TestBytesToBytesModBN(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn, err := Int2ModBN(19, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn.Free()

    newmodbn, err := Bytes2ModBN(modbn.ToBytes(), curve)
    if err != nil {
        t.Error(err)
    }
    defer newmodbn.Free()

    if !modbn.Equals(newmodbn) {
        t.Error("The two ModBigNum's were not equal")
    }
}

func TestEquals(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    modbn3, err := Int2ModBN(10, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn3.Free()

    modbn4, err := Int2ModBN(3, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn4.Free()

    if !modbn1.Equals(modbn2) {
        t.Error("The two ModBigNum's were not equal")
    }

    if modbn1.Equals(modbn3) {
        t.Error("The two ModBigNum's were equal")
    }

    if modbn1.Equals(modbn4) {
        t.Error("The two ModBigNum's were equal")
    }
}

func TestCompare(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    modbn3, err := Int2ModBN(10, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn3.Free()

    modbn4, err := Int2ModBN(3, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn4.Free()

    if modbn1.Compare(modbn2) != 0 {
        t.Error("The two ModBigNum's were not equal")
    }

    if !(modbn1.Compare(modbn3) < 0) {
        t.Error("Expected modbn1 to be less than modbn3, or -1")
    }

    if !(modbn1.Compare(modbn4) > 0) {
        t.Error("Expected modbn1 to be greater than modbn4, or 1")
    }
}

func TestPow(t *testing.T) {
    t.Run("small powers", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        modbn1, err := Int2ModBN(2, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn1.Free()

        modbn2, err := Int2ModBN(5, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn2.Free()

        // 2^5 % curve.Order
        err = modbn1.Pow(modbn2)
        if err != nil {
            t.Error(err)
        }

        t.Log(BNToDecStr(modbn1.Bignum))

        goBN1 := big.NewInt(2)
        goBN2 := big.NewInt(5)
        bytes := BNToBytes(curve.Order)
        var order *big.Int = big.NewInt(0)
        order.SetBytes(bytes)
        goBN1.Exp(goBN1, goBN2, order)

        bn := BigIntToBN(goBN1)
        modbn3, err := GetNewModBN(bn, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn3.Free()

        if !modbn1.Equals(modbn3) {
            t.Error("modbn1 doesn't equal modbn3 which was converted from a Go big.Int")
        }
    })
    t.Run("big powers", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        modbn1, err := Int2ModBN(2, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn1.Free()

        modbn2, err := Int2ModBN(300, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn2.Free()

        // 2^5 % curve.Order
        err = modbn1.Pow(modbn2)
        if err != nil {
            t.Error(err)
        }

        t.Log(BNToDecStr(modbn1.Bignum))

        goBN1 := big.NewInt(2)
        goBN2 := big.NewInt(300)
        bytes := BNToBytes(curve.Order)
        var order *big.Int = big.NewInt(0)
        order.SetBytes(bytes)
        goBN1.Exp(goBN1, goBN2, order)

        bn := BigIntToBN(goBN1)
        modbn3, err := GetNewModBN(bn, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn3.Free()

        if !modbn1.Equals(modbn3) {
            t.Error("modbn1 doesn't equal modbn3 which was converted from a Go big.Int")
        }
    })
}

func TestMul(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(2, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(300, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    // 2^5 % curve.Order
    err = modbn1.Mul(modbn2)
    if err != nil {
        t.Error(err)
    }

    modbn3, err := Int2ModBN(600, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn3.Free()

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 600")
    }
}

func TestDiv(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(568, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(32, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    err = modbn1.Div(modbn2)
    if err != nil {
        t.Error(err)
    }
}

func TestAdd(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    err = modbn1.Add(modbn2)
    if err != nil {
        t.Error(err)
    }

    modbn3, err := Int2ModBN(768, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn3.Free()

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 768")
    }
}

func TestSub(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    err = modbn1.Sub(modbn2)
    if err != nil {
        t.Error(err)
    }

    modbn3, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn3.Free()

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 768")
    }
}

func TestInverse(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn.Free()

    err = modbn.Invert()
    if err != nil {
        t.Error(err)
    }
}

func TestMod(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    modbn1, err := Int2ModBN(768, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    err = modbn1.Mod(modbn2)
    if err != nil {
        t.Error(err)
    }
}
