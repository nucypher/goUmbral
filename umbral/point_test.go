package umbral

import (
    "testing"
)

func TestNewPoint(t *testing.T) {
    t.Run("point provided", func(t *testing.T) {
        curve := GetNewCurve(SECP256R1)
        defer curve.Free()

        ecPoint := GetNewECPoint(curve)

        point := GetNewPoint(ecPoint, curve)
        defer point.Free()

        if point.ECPoint == nil {
            t.Error("The point was nil.")
        }
    })
    t.Run("point nil", func(t *testing.T) {
        curve := GetNewCurve(SECP256R1)
        defer curve.Free()

        point := GetNewPoint(nil, curve)
        defer point.Free()

        if point.ECPoint == nil {
            t.Error("The point was nil.")
        }
    })
    t.Run("curve nil", func(t *testing.T) {
        curve := GetNewCurve(SECP256R1)
        defer curve.Free()

        // Setting everything else to nil should still succeed.
        curve.NID = 0
        curve.Generator = nil

        point := GetNewPoint(nil, curve)

        point.Free()
    })
}

func TestGenRandPoint(t *testing.T) {
    curve := GetNewCurve(SECP256K1)
    defer curve.Free()

    point := GenRandPoint(curve)
    defer point.Free()

    if point.ECPoint == nil {
        t.Error("The returned random EC_POINT was nil")
    }
}

func TestPointToFromAffine(t *testing.T) {
    curve := GetNewCurve(SECP256K1)
    defer curve.Free()

    point := GenRandPoint(curve)
    defer point.Free()

    x, y := point.ToAffine()

    point2 := Affine2Point(x, y, curve)
    defer point2.Free()

    if !point.Equals(point2) {
        t.Error("The points were not equal")
    }
}

/*
func TestPointToFromBytes(t *testing.T) {
    curve := GetNewCurve(SECP256K1)
    defer curve.Free()

    point := GenRandPoint(curve)
    defer point.Free()

    point2 := Bytes2Point(point.ToBytes(), curve)
    defer point2.Free()

    if !point.Equals(point2) {
        t.Error("The points were not equal")
    }
}
*/

func TestPointMul(t *testing.T) {

}

func TestPointAdd(t *testing.T) {

}

func TestPointSub(t *testing.T) {

}

func TestPointInvert(t *testing.T) {

}

func TestUnsafeHashToPoint(t *testing.T) {

}

func TestPointCopy(t *testing.T) {

}

func TestPointFree(t *testing.T) {

}
