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

func (m Curve) Copy() (Curve, error) {
    // Return a deep copy of a Curve.
    group := C.EC_GROUP_dup(m.Group)
    if unsafe.Pointer(group) == C.NULL {
        return Curve{}, errors.New("EC_GROUP_dup failure")
    }
    order := C.BN_dup(m.Order)
    if unsafe.Pointer(order) == C.NULL {
        return Curve{}, errors.New("BN_dup failure")
    }
    generator := C.EC_POINT_dup(m.Generator, group)
    if unsafe.Pointer(generator) == C.NULL {
        return Curve{}, errors.New("EC_POINT_dup failure")
    }
    return Curve{m.NID, group, order, generator}, nil
}

func (m *Curve) Free() {
    FreeECGroup(m.Group)
    FreeBigNum(m.Order)
    FreeECPoint(m.Generator)
}
