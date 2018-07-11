package umbral

// #include "shim.h"
import "C"
import (
    "unsafe"
    "log"
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
    // Generate a new Point struct based on the arguments provided.
    //
    // If point is nil then GetNewPoint will generate a new cryptographically secure
    // ECPoint and check for errors before returning the new Point.
    //
    // if point is nil AND the curve group is also nil then
    // GetNewPoint will fail and return the error.
    if point == nil {
        newPoint := GenRandPoint(curve)
        return newPoint
    }
    return Point{ECPoint: point, Curve: curve}
}

func PointLength(curve Curve) {
    // TODO: Return the size of a point given the curve.
}

func GenRandPoint(curve Curve) Point {
    // Returns a Point struct with a cryptographically
    // secure EC_POINT based on the provided curve.
    randPoint := GetNewECPoint(curve)

    randModBN, err := GenRandModBN(curve)
    if err != nil {
        log.Fatal(err)
    }
    defer randModBN.Free()

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(curve.Group, randPoint, (*C.BIGNUM)(C.NULL),
        curve.Generator, randModBN.Bignum, ctx)

    if result != 1 {
        log.Fatal("EC_POINT_mul failure")
    }

    return Point{ECPoint: randPoint, Curve: curve}
}

func Affine2Point(affineX, affineY *big.Int, curve Curve) Point {
    /*
    Returns a Point object from the given affine coordinates.
    */
    x := BigIntToBN(affineX)
    y := BigIntToBN(affineY)
    if !BNIsWithinOrder(x, curve) || !BNIsWithinOrder(y, curve) {
        log.Fatal("x or y are not within the curve")
    }
    point := GetECPointFromAffine(x, y, curve)

    return Point{ECPoint: point, Curve: curve}
}

func (m Point) ToAffine() (*big.Int, *big.Int) {
    /*
    Returns an x and y coordinate of the Point as a Go big.Int.
    */
    xBN, yBN := GetAffineCoordsFromECPoint(m.ECPoint, m.Curve)
    defer FreeBigNum(xBN)
    defer FreeBigNum(yBN)

    goX := BNToBigInt(xBN)
    goY := BNToBigInt(yBN)
    return goX, goY
}

func Bytes2Point(data []byte, curve Curve) Point {
    if len(data) == 0 {
        log.Fatal("No bytes failure")
    }

    // TODO: Implement this when PointLength is finished.
    return Point{}
}

func (m Point) ToBytes() []byte {
    x, y := m.ToAffine()
    // TODO: Uncompressed vs Compressed
    return append(x.Bytes(), y.Bytes()...)
}

func GetPointFromGenerator(curve Curve) (ECPoint, Curve) {
    // Consider making a copy of this point
    // so there are not any double frees.
    return curve.Generator, curve
}

func (m *Point) Equals(other Point) bool {
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_cmp(m.Curve.Group, m.ECPoint, other.ECPoint, ctx)
    if result == -1 {
        log.Fatal("EC_POINT_cmp failure")
    }
    return result == 0
}

func (z *Point) Mul(x *Point, y *ModBigNum) *Point {
    // Sets 'z' to the EC_POINT_mul of an EC_POINT 'x' and a BIGNUM 'y'.
    // Returns 'z'.
    product := GetNewECPoint(x.Curve)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(x.Curve.Group, product, (*C.BIGNUM)(C.NULL),
        x.ECPoint, y.Bignum, ctx)
    if result != 1 {
        log.Fatal("EC_POINT_mul failure")
    }
    FreeECPoint(z.ECPoint)

    z.ECPoint = product
    return z
}

func (z *Point) Add(x, y *Point) *Point {
    // Sets 'z' to the EC_POINT_add of two EC_POINTS 'x' and 'y'.
    // Returns 'z'.
    sum := GetNewECPoint(x.Curve)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_add(x.Curve.Group, sum, x.ECPoint, y.ECPoint, ctx)
    if result != 1 {
        log.Fatal("EC_POINT_add failure")
    }

    FreeECPoint(z.ECPoint)

    z.ECPoint = sum
    return z
}

func (z *Point) Sub(x, y *Point) *Point {
    // Sets 'z' to 'x' sub 'y' by adding via the inverse.
    // Returns 'z'.
    tmp := y.Copy()
    defer tmp.Free()

    return z.Add(x, tmp.Invert())
}

func (z *Point) Invert() *Point {
    // Sets 'z' to its inverse.
    // Returns 'z'.
    inverse := C.EC_POINT_dup(z.ECPoint, z.Curve.Group)

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_invert(z.Curve.Group, inverse, ctx)
    if result != 1 {
        log.Fatal("EC_POINT_invert failure")
    }

    FreeECPoint(z.ECPoint)

    z.ECPoint = inverse
    return z
}

func UnsafeHashToPoint() {
    // TODO: Hash arbitrary data into a valid EC point.
}

func (m *Point) Copy() *Point {
    // Deep copy of a Point EXCLUDING the curve.
    point := C.EC_POINT_dup(m.ECPoint, m.Curve.Group)
    if unsafe.Pointer(point) == C.NULL {
        log.Fatal("EC_POINT_dup failure")
    }

    return &Point{ECPoint: point, Curve: m.Curve}
}

func (m *Point) Free() {
    FreeECPoint(m.ECPoint)
    // Do not free the curve.
    // m.Curve.Free()
}
