package umbral

import (
    "testing"
)

func TestNewPoint(t *testing.T) {
    t.Run("point provided", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        ecPoint, err := GetNewECPoint(curve)
        if err != nil {
            t.Error(err)
        }
        point, err := GetNewPoint(ecPoint, curve)
        if err != nil {
            t.Error(err)
        }
        defer point.Free()

        if point.ECPoint == nil {
            t.Error("The point was nil.")
        }
    })
    t.Run("point nil", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        point, err := GetNewPoint(nil, curve)
        if err != nil {
            t.Error(err)
        }
        defer point.Free()

        if point.ECPoint == nil {
            t.Error("The point was nil.")
        }
    })
    t.Run("curve group nil", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        // Setting the EC_GROUP to nil should cause this to fail.
        curve.Group = nil
        _, err = GetNewPoint(nil, curve)
        if err == nil {
            t.Error("Should have returned an error: 'New EC Point Failure'")
        }
    })
    t.Run("curve order nil", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        // Setting the order of the curve to nil should cause this to fail.
        curve.Order = nil
        _, err = GetNewPoint(nil, curve)
        if err == nil {
            t.Error("Should have returned an error: The order of the curve is nil")
        }
    })
    t.Run("curve nil", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        defer curve.Free()

        // Setting everything else to nil should still succeed.
        curve.NID = 0
        curve.Generator = nil
        point, err := GetNewPoint(nil, curve)
        if err != nil {
            t.Error(err)
        }
        point.Free()
    })
}

func TestGenRandPoint(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    if point.ECPoint == nil {
        t.Error("The returned random EC_POINT was nil")
    }
}

func TestPointToFromAffine(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    x, y, err := point.ToAffine()
    if err != nil {
        t.Error(err)
    }

    point2, err := Affine2Point(x, y, curve)
    if err != nil {
        t.Error(err)
    }
    defer point2.Free()

    equal, err := point.Equals(point2)
    if err != nil {
        t.Error(err)
    }

    if !equal {
        t.Error("The points were not equal")
    }
}

func TestPointToFromBytes(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    t.Run("uncompressed", func(t *testing.T) {
        bytes, err := point.ToBytes(false)
        if err != nil {
            t.Error(err)
        }

        point2, err := Bytes2Point(bytes, curve)
        if err != nil {
            t.Error(err)
        }
        defer point2.Free()

        equal, err := point.Equals(point2)
        if err != nil {
            t.Error(err)
        }

        if !equal {
            t.Error("The points were not equal")
        }
    })
    t.Run("compressed", func(t *testing.T) {
        bytes, err := point.ToBytes(true)
        if err != nil {
            t.Error(err)
        }

        point2, err := Bytes2Point(bytes, curve)
        if err != nil {
            t.Error(err)
        }
        defer point2.Free()

        equal, err := point.Equals(point2)
        if err != nil {
            t.Error(err)
        }

        if !equal {
            t.Error("The points were not equal")
        }
    })
}

func TestPointMul(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    modbn, err := GenRandModBN(curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn.Free()

    err = point.Mul(modbn)
    if err != nil {
        t.Error(err)
    }
}

func TestPointAdd(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point1, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point1.Free()

    point2, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point2.Free()

    err = point1.Add(point2)
    if err != nil {
        t.Error(err)
    }
}

func TestPointSub(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point1, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point1.Free()

    point2, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point2.Free()

    err = point1.Sub(point2)
    if err != nil {
        t.Error(err)
    }
}

func TestPointInvert(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    err = point.Invert()
    if err != nil {
        t.Error(err)
    }
}

func TestUnsafeHashToPoint(t *testing.T) {
}

func TestPointCopy(t *testing.T) {
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    point, err := GenRandPoint(curve)
    if err != nil {
        t.Error(err)
    }
    defer point.Free()

    point2, err := point.Copy()
    if err != nil {
        t.Error(err)
    }
    defer point2.Free()

    if point.ECPoint == point2.ECPoint {
        t.Error("The pointers were equal after a copy.")
    }

    if equ, err := point.Equals(point2); err != nil || !equ {
        t.Error("The points were not equal.")
    }
}
