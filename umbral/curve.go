package umbral

// #include "shim.h"
import "C"
import (
    "log"
)

// primCurve typedef allows for compile time type checking.
type primCurve int

// Supported curves
const (
    SECP256R1 primCurve = 415
    SECP256K1 primCurve = 714
    SECP384R1 primCurve = 715
)

type Curve struct {
    NID int
    Group ECGroup
    Order BigNum
    Generator ECPoint
}

func GetNewCurve(prim primCurve) Curve {
    // Do not use cast from an int to a primCurve with an unsupported curve nid.
    // Use the constant curve values above instead.

    // Runtime check below just to be sure.
    // Could default to a certain curve instead of closing.
    switch prim {
    case SECP256R1:
    case SECP256K1:
    case SECP384R1:
    default:
        log.Fatal("The curve:", prim, "is not supported.")
    }
    group := GetECGroupByCurveNID(int(prim))
    order := GetECOrderByGroup(group)
    generator := GetECGeneratorByGroup(group)
    return Curve{NID: int(prim), Group: group, Order: order, Generator: generator}
}

func (m Curve) Equals(other Curve) bool {
    return m.NID == other.NID
}
