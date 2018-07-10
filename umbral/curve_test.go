package umbral

import (
    "testing"
)

func TestNewCurve(t *testing.T) {
    curve, err := GetNewCurve(SECP256R1)
    if err != nil {
        t.Error(err)
    }
    curve.Free()

    curve, err = GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }
    curve.Free()

    curve, err = GetNewCurve(SECP384R1)
    if err != nil {
        t.Error(err)
    }
    curve.Free()
}

func TestEqualCurves(t *testing.T) {
    curve1, err1 := GetNewCurve(SECP256R1)
    if err1 != nil {
        t.Error(err1)
    }
    defer curve1.Free()

    curve2, err2 := GetNewCurve(SECP256R1)
    if err2 != nil {
        t.Error(err2)
    }
    defer curve2.Free()

    if !curve1.Equals(curve2) {
        t.Error("Equal curves did not return equal.")
    }
}

func TestFree(t *testing.T) {
    // Stress test for memeory leaks.
    // Leaks are more obvious when there is a lot of lost memory.
    for i := 0; i < 10000; i++ {
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }

        curve.Free()
    }
}
