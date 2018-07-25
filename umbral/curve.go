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

// #include "shim.h"
import "C"
import (
    "errors"
    "unsafe"
)

// Supported curves
const (
    SECP256R1 = C.NID_X9_62_prime256v1
    SECP256K1 = C.NID_secp256k1
    SECP384R1 = C.NID_secp384r1
)

type Curve struct {
    NID int
    Group ECGroup
    Order BigNum
    Generator ECPoint
}

func GetNewCurve(nid C.int) (Curve, error) {
    // Do not use cast from an int to a C.int with an unsupported curve nid.
    // Use the constant curve values above instead.

    // Runtime check below just to be sure.
    // Could default to a certain curve instead of closing.
    switch nid {
    case SECP256R1:
    case SECP256K1:
    case SECP384R1:
    default:
        return Curve{}, errors.New("This curve is not supported. Please use one of the constant curves defined in curve.go.")
    }
    group := GetECGroupByCurveNID(int(nid))
    order := GetECOrderByGroup(group)
    generator := GetECGeneratorByGroup(group)
    return Curve{NID: int(nid), Group: group, Order: order, Generator: generator}, nil
}

func (m Curve) Equals(other Curve) bool {
    return m.NID == other.NID
}

func (m Curve) FieldOrderSize() uint {
    bits := GetECGroupDegree(m.Group)
    return (bits + 7) / 8
}

func (m *Curve) Free() {
    FreeBigNum(m.Order)
    FreeECGroup(m.Group)
    // The generator is already freed by freeing the EC_GROUP.
    // FreeECPoint(m.Generator)
}
