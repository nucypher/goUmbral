package umbral

import (
    "testing"
)

func TestNewCurve(t *testing.T) {
    _, err := GetNewCurve(SECP256R1)
    if err != nil {
        t.Error(err)
    }

    _, err = GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    _, err = GetNewCurve(SECP384R1)
    if err != nil {
        t.Error(err)
    }
}

func TestEqualCurves(t *testing.T) {
    curve1, err1 := GetNewCurve(SECP256R1)
    if err1 != nil {
        t.Error(err1)
    }

    curve2, err2 := GetNewCurve(SECP256R1)
    if err2 != nil {
        t.Error(err2)
    }

    if !curve1.Equals(curve2) {
        t.Error("Equal curves did not return equal.")
    }
}
