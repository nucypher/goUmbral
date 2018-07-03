package umbral

// #include "shim.h"
import "C"
import (
    "log"
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

func GetNewCurve(nid C.int) Curve {
    // Do not use cast from an int to a C.int with an unsupported curve nid.
    // Use the constant curve values above instead.

    // Runtime check below just to be sure.
    // Could default to a certain curve instead of closing.
    switch nid {
    case SECP256R1:
    case SECP256K1:
    case SECP384R1:
    default:
        log.Fatal("The curve:", int(nid), "is not supported.")
    }
    group := GetECGroupByCurveNID(int(nid))
    order := GetECOrderByGroup(group)
    generator := GetECGeneratorByGroup(group)
    return Curve{NID: int(nid), Group: group, Order: order, Generator: generator}
}

func (m Curve) Equals(other Curve) bool {
    return m.NID == other.NID
}
