package umbral

import (
    "golang.org/x/crypto/blake2b"
    "math/big"
    "encoding/binary"
    "testing"
)

func TestNewModBN(t *testing.T) {
    t.Run("bn=5", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        bn := IntToBN(5)
        // Should succeed.
        _, err = GetNewModBN(bn, curve)
        if err != nil {
            t.Error(err)
        }
    })
    t.Run("bn=-10", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        // IntToBN is unsigned.
        onebn := IntToBN(1)
        tenbn := IntToBN(10)
        negbn := SubBN(onebn, tenbn)
        // Should fail.
        _, err = GetNewModBN(negbn, curve)
        if err == nil {
            t.Error("A negative bignum should not be within the order of the curve")
        }
    })
}

func TestGenRandBN(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    one := IntToBN(1)
    defer FreeBigNum(one)

    for i := 0; i < 1000; i++ {
        rand, err := GenRandModBN(curve)
        if err != nil {
            t.Error(err)
        }

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

    Int2ModBN(10, curve)
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

        // Convert to BN with Hash2BN.
        bn, err := Hash2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }

        // Hash the number with blake2b and convert to Go big.Int.
        blake2b, err := blake2b.New(64, bs)
        if err != nil {
            t.Error(err)
        }
        var hashContainer []byte
        blake2b.Sum(hashContainer)
        goBN := big.NewInt(0)
        goBN.SetBytes(hashContainer)

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
        _, err = Hash2ModBN(bs, curve)
        if err == nil {
            t.Error("An empty byte array returned a valid bignum.")
        }
    })

    t.Run("bs>64", func(t *testing.T) {
        // Test a key size greater than 64 bytes long
        bs := make([]byte, 128)
        bs[127] = byte(42)
        bs[100] = byte(52)
        curve, err := GetNewCurve(SECP384R1)
        if err != nil {
            t.Error(err)
        }
        _, err = Hash2ModBN(bs, curve)
        if err == nil {
            t.Error("An byte array of 128 returned a valid bignum.")
        }
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

        _, err = Bytes2ModBN(bs, curve)
        if err != nil {
            t.Error(err)
        }
    })

    t.Run("empty", func(t *testing.T) {
        var bs []byte
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }
        _, err = Bytes2ModBN(bs, curve)
        if err == nil {
            t.Error("An empty byte array returned a valid bignum.")
        }
    })
}

func TestBytesToBytesModBN(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn, err := Int2ModBN(19, curve)
    if err != nil {
        t.Error(err)
    }

    newmodbn, err := Bytes2ModBN(modbn.ToBytes(), curve)
    if err != nil {
        t.Error(err)
    }

    if !modbn.Equals(newmodbn) {
        t.Error("The two ModBigNum's were not equal")
    }
}

func TestEquals(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn1, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }

    modbn3, err := Int2ModBN(10, curve)
    if err != nil {
        t.Error(err)
    }

    modbn4, err := Int2ModBN(3, curve)
    if err != nil {
        t.Error(err)
    }

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

    modbn1, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(5, curve)
    if err != nil {
        t.Error(err)
    }

    modbn3, err := Int2ModBN(10, curve)
    if err != nil {
        t.Error(err)
    }

    modbn4, err := Int2ModBN(3, curve)
    if err != nil {
        t.Error(err)
    }

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

        modbn1, err := Int2ModBN(2, curve)
        if err != nil {
            t.Error(err)
        }

        modbn2, err := Int2ModBN(5, curve)
        if err != nil {
            t.Error(err)
        }

        // 2^5 % curve.Order
        modbn1.Pow(modbn2)
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

        if !modbn1.Equals(modbn3) {
            t.Error("modbn1 doesn't equal modbn3 which was converted from a Go big.Int")
        }
    })
    t.Run("big powers", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }

        modbn1, err := Int2ModBN(2, curve)
        if err != nil {
            t.Error(err)
        }

        modbn2, err := Int2ModBN(300, curve)
        if err != nil {
            t.Error(err)
        }

        // 2^5 % curve.Order
        modbn1.Pow(modbn2)
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

    modbn1, err := Int2ModBN(2, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(300, curve)
    if err != nil {
        t.Error(err)
    }

    // 2^5 % curve.Order
    modbn1.Mul(modbn2)

    modbn3, err := Int2ModBN(600, curve)
    if err != nil {
        t.Error(err)
    }

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 600")
    }
}

func TestDiv(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn1, err := Int2ModBN(568, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(32, curve)
    if err != nil {
        t.Error(err)
    }

    modbn1.Div(modbn2)
}

func TestAdd(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn1, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }

    modbn1.Add(modbn2)

    modbn3, err := Int2ModBN(768, curve)
    if err != nil {
        t.Error(err)
    }

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 768")
    }
}

func TestSub(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn1, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }

    modbn1.Sub(modbn2)

    modbn3, err := Int2ModBN(256, curve)
    if err != nil {
        t.Error(err)
    }

    if !modbn1.Equals(modbn3) {
        t.Error("modbn1 doesn't equal modbn3: 768")
    }
}

func TestInverse(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }
    modbn.Inverse()
}

func TestMod(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    modbn1, err := Int2ModBN(768, curve)
    if err != nil {
        t.Error(err)
    }

    modbn2, err := Int2ModBN(512, curve)
    if err != nil {
        t.Error(err)
    }

    modbn1.Mod(modbn2)
}
