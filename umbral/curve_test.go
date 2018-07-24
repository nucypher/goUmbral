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
    // Stress test for memory leaks.
    // Leaks are more obvious when there is a lot of lost memory.
    for i := 0; i < 10000; i++ {
        curve, err := GetNewCurve(SECP256K1)
        if err != nil {
            t.Error(err)
        }

        curve.Free()
    }
}

func TestCopy(t *testing.T) {
    // Stress test for memory leaks.
    // Leaks are more obvious when there is a lot of lost memory.
    curve, err := GetNewCurve(SECP256K1)
    if err != nil {
        t.Error(err)
    }

    for i := 0; i < 10000; i++ {
        curve2, err := curve.Copy()
        if err != nil {
            t.Error(err)
        }

        curve2.Free()
    }
}
