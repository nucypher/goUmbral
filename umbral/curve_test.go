package umbral

import (
    "testing"
)

func TestNewCurve(t *testing.T) {
    curve := GetNewCurve(SECP256R1)
    curve.Free()

    curve = GetNewCurve(SECP256K1)
    curve.Free()

    curve = GetNewCurve(SECP384R1)
    curve.Free()
}

func TestEqualCurves(t *testing.T) {
    curve1 := GetNewCurve(SECP256R1)
    defer curve1.Free()

    curve2 := GetNewCurve(SECP256R1)
    defer curve2.Free()

    if !curve1.Equals(curve2) {
        t.Error("Equal curves did not return equal.")
    }
}

func TestFree(t *testing.T) {
    // Stress test for memory leaks.
    // Leaks are more obvious when there is a lot of lost memory.
    for i := 0; i < 10000; i++ {
        curve := GetNewCurve(SECP256K1)

        curve.Free()
    }
}

func TestCopy(t *testing.T) {
    // Stress test for memory leaks.
    // Leaks are more obvious when there is a lot of lost memory.
    curve := GetNewCurve(SECP256K1)
    defer curve.Free()

    for i := 0; i < 10000; i++ {
        curve2 := curve.Copy()

        curve2.Free()
    }
}
