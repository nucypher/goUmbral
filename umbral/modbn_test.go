package umbral

import (
    "golang.org/x/crypto/blake2b"
    "math/big"
    "encoding/binary"
    "testing"
)

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
}
