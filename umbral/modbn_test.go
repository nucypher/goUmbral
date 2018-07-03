package umbral

import (
    "golang.org/x/crypto/blake2b"
    "math/big"
    "encoding/binary"
    "testing"
)

func TestNewModBN(t *testing.T) {
    t.Run("bn=5", func(t *testing.T) {
        curve := GetNewCurve(SECP256R1)
        bn := IntToBN(5)
        // Should succeed.
        GetNewModBN(bn, curve)
    })
    t.Run("bn=-10", func(t *testing.T) {
        curve := GetNewCurve(SECP256R1)
        negbn := IntToBN(-10)
        // Should fail.
        GetNewModBN(negbn, curve)
        if !t.Failed() {
            t.Error("A negative bignum should not be within the order of the curve")
        }
    })
}

func TestGenRandBN(t *testing.T) {
    curve := GetNewCurve(SECP256K1)

    one := IntToBN(1)
    defer FreeBigNum(one)

    for i := 0; i < 1000; i++ {
        rand := GenRandModBN(curve)

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
    curve := GetNewCurve(SECP384R1)

    Int2ModBN(10, curve)
}

func TestHash2BN(t *testing.T) {
    // Choose a number.
    bs := make([]byte, 4)
    binary.BigEndian.PutUint32(bs, 999111777)

    // Get the curve.
    curve := GetNewCurve(SECP256K1)

    // Convert to BN with Hash2BN.
    bn := Hash2ModBN(bs, curve)

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


    t.Run("bs=0", func(t *testing.T) {
        // Test an empty byte array.
        var bs []byte
        curve := GetNewCurve(SECP256K1)
        Hash2ModBN(bs, curve)
        if !t.Failed() {
            t.Error("An empty byte array returned a valid bignum.")
        }
    })

    t.Run("bs>64", func(t *testing.T) {
        // Test a key size greater than 64 bytes long
        bs := make([]byte, 128)
        bs[127] = byte(42)
        bs[100] = byte(52)
        curve := GetNewCurve(SECP384R1)
        Hash2ModBN(bs, curve)
        if !t.Failed() {
            t.Error("An byte array of 128 returned a valid bignum.")
        }
    })
}

func TestBytesToModBN(t *testing.T) {
    bs := make([]byte, 4)
    binary.BigEndian.PutUint32(bs, 999111777)

    curve := GetNewCurve(SECP256K1)

    Bytes2ModBN(bs, curve)
}

func TestBytesToModBNFailure(t *testing.T) {
    var bs []byte
    curve := GetNewCurve(SECP256K1)
    Bytes2ModBN(bs, curve)
    if !t.Failed() {
        t.Error("An empty byte array returned a valid bignum.")
    }
}

func TestBytesToBytesModBN(t *testing.T) {
    curve := GetNewCurve(SECP256K1)

    modbn := Int2ModBN(19, curve)

    newmodbn := Bytes2ModBN(modbn.ToBytes(), curve)

    if !modbn.Equals(newmodbn) {
        t.Error("The two ModBigNum's were not equal")
    }
}
