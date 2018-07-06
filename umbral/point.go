package umbral

// #include "shim.h"
import "C"
import (
    "unsafe"
    "errors"
    "math/big"
)

/*
Represents an OpenSSL EC_POINT.
*/

type Point struct {
   ECPoint ECPoint
   Curve Curve
}

func GetNewPoint(point ECPoint, curve Curve) Point {
    return Point{ECPoint: point, Curve: curve}
}

func PointLength(curve Curve) {
    // TODO: Return the size of a point given the curve.
}

func GenRandPoint(curve Curve) (Point, error) {
    /*
    Returns a Point struct with a cryptographically secure EC_POINT based
    on the provided curve.
    */
    randPoint := GetNewECPoint(curve)

    randModBN, err := GenRandModBN(curve)
    if err != nil {
        return Point{}, err
    }
    randBN := randModBN.Bignum

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(curve.Group, randPoint, (*C.BIGNUM)(C.NULL),
        curve.Generator, randBN, ctx)

    if result != 1 {
        return Point{}, errors.New("EC_POINT_mul failure")
    }

    return Point{ECPoint: randPoint, Curve: curve}, nil
}

func Affine2Point(affineX, affineY *big.Int, curve Curve) (Point, error) {
    /*
    Returns a Point object from the given affine coordinates.
    */
    x := BigIntToBN(affineX)
    y := BigIntToBN(affineY)
    if !BNIsWithinOrder(x, curve) || !BNIsWithinOrder(y, curve) {
        return Point{}, errors.New("x or y are not within the curve")
    }
    point, err := GetECPointFromAffine(x, y, curve)
    if err != nil {
        return Point{}, err
    }

    return Point{ECPoint: point, Curve: curve}, nil
}

func (m Point) ToAffine() (*big.Int, *big.Int, error) {
    /*
    Returns an x and y coordinate of the Point as a Go big.Int.
    */
    xBN, yBN, err := GetAffineCoordsFromECPoint(m.ECPoint, m.Curve)
    defer FreeBigNum(xBN)
    defer FreeBigNum(yBN)
    if err != nil {
        return nil, nil, err
    }
    goX := BNToBigInt(xBN)
    goY := BNToBigInt(yBN)
    return goX, goY, nil
}

func Bytes2Point(data []byte, curve Curve) (Point, error) {
    if len(data) == 0 {
        return Point{}, errors.New("No bytes failure")
    }

    // TODO: Implement this when PointLength is finished.
    return Point{}, nil
}

func (m Point) ToBytes() ([]byte, error) {
    x, y, err := m.ToAffine()
    if err != nil {
        return nil, err
    }
    // TODO: Uncompressed vs Compressed
    return append(x.Bytes(), y.Bytes()...), nil
}

func GetPointFromGenerator(curve Curve) (ECPoint, Curve) {
    return curve.Generator, curve
}

func (m Point) Equals(other Point) (bool, error) {
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_cmp(m.Curve.Group, m.ECPoint, other.ECPoint, ctx)
    if result == -1 {
        return false, errors.New("EC_POINT_cmp failure")
    }
    return result == 0, nil
}

func (m *Point) Mul(other ModBigNum) error {
    /*
    Performs a EC_POINT_mul on an EC_POINT and a BIGNUM.
    */
    if !m.Curve.Equals(other.Curve) {
        return errors.New("The points do not share the same curve.")
    }
    product := GetNewECPoint(m.Curve)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(m.Curve.Group, product, (*C.BIGNUM)(C.NULL),
        m.ECPoint, other.Bignum, ctx)
    if result != 1 {
        return errors.New("EC_POINT_mul failure")
    }
    FreeECPoint(m.ECPoint)

    m.ECPoint = product
    return nil
}

func (m *Point) Add(other Point) error {
    // Performs an EC_POINT_add on two EC_POINTS.
    sum := GetNewECPoint(m.Curve)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_add(m.Curve.Group, sum, m.ECPoint, other.ECPoint, ctx)
    if result != 1 {
        return errors.New("EC_POINT_add failure")
    }

    FreeECPoint(m.ECPoint)

    m.ECPoint = sum
    return nil
}

func (m *Point) Sub(other Point) error {
    // Performs an subtraction on two EC_POINTS by adding by the inverse.
    tmp, err := other.Copy()
    if err != nil {
        return err
    }
    defer tmp.Free()

    err = tmp.Invert()
    if err != nil {
        return err
    }

    err = m.Add(tmp)
    if err != nil {
        return err
    }

    return nil
}

func (m *Point) Invert() error {
    inverse := C.EC_POINT_dup(m.ECPoint, m.Curve.Group)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_invert(m.Curve.Group, inverse, ctx)
    if result != 1 {
        return errors.New("EC_POINT_invert failure")
    }

    FreeECPoint(m.ECPoint)

    m.ECPoint = inverse
    return nil
}

func UnsafeHashToPoint() {
    // TODO: Hash arbitrary data into a valid EC point.
}

func (m Point) Copy() (Point, error) {
    // Deep copy of a Point.
    point := C.EC_POINT_dup(m.ECPoint, m.Curve.Group)
    if unsafe.Pointer(point) == C.NULL {
        return Point{}, errors.New("EC_POINT_dup failure")
    }
    curve, err := m.Curve.Copy()
    if err != nil {
        return Point{}, err
    }

    return Point{ECPoint: point, Curve: curve}, nil
}

func (m Point) Free() {
    FreeECPoint(m.ECPoint)
    m.Curve.Free()
}
