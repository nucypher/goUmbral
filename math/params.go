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
package math

import (
    "github.com/nucypher/goUmbral/openssl"
)

type UmbralParameters struct {
    Curve *openssl.Curve
    Size uint
    G *Point
    U *Point
}

func NewUmbralParameters(curve *openssl.Curve) (*UmbralParameters, error) {
    var params UmbralParameters
    params.Curve = curve
    params.Size = curve.FieldOrderSize()

    params.G = GetGeneratorFromCurve(curve)
    gBytes, err := params.G.ToBytes(true)
    if err != nil {
        return nil, err
    }

    parametersSeed := []byte("NuCypher/UmbralParameters/")

    parametersSeed = append(parametersSeed, byte('u'))

    params.U, err = UnsafeHashToPoint(gBytes, &params, parametersSeed)
    if err != nil {
        return nil, err
    }
    return &params, nil
}

func (m *UmbralParameters) Equals(other *UmbralParameters) bool {
    // TODO: This is not comparing the order, which currently is an OpenSSL pointer

    eCurve := m.Curve.Equals(other.Curve)

    eSize := (m.Size == other.Size)

    eG, err := m.G.Equals(other.G)
    if err != nil {
        // Could return the error.
        return false
    }

    eU, err := m.U.Equals(other.U)
    if err != nil {
        // Could return the error.
        return false
    }

    return eCurve && eSize && eG && eU
}
