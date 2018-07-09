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
        ecPoint, err := GetNewECPoint(curve)
        if err != nil {
            t.Error(err)
        }
        point, err := GetNewPoint(ecPoint, curve)
        if err != nil {
            t.Error(err)
        }
        if point.ECPoint == nil {
            t.Error("The point was nil.")
        }
    })
    t.Run("point nil", func(t *testing.T) {
        curve, err := GetNewCurve(SECP256R1)
        if err != nil {
            t.Error(err)
        }
        point, err := GetNewPoint(nil, curve)
        if err != nil {
            t.Error(err)
        }
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
        // Setting everything else to nil should still succeed.
        curve.NID = 0
        curve.Generator = nil
        _, err = GetNewPoint(nil, curve)
        if err != nil {
            t.Error(err)
        }
    })
}

func TestGenRandPoint(t *testing.T) {

}
