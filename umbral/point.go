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

func GetNewPoint(point ECPoint, curve Curve) (Point, error) {
    // Generate a new Point struct based on the arguments provided.
    //
    // If point is nil then GetNewPoint will generate a new cryptographically secure
    // ECPoint and check for errors before returning the new Point.
    //
    // if point is nil AND the curve group is also nil then
    // GetNewPoint will fail and return the error.
    var err error = nil
    if point == nil {
        newPoint, err := GenRandPoint(curve)
        if err != nil {
            return Point{}, err
        }
        return newPoint, err
    }
    return Point{ECPoint: point, Curve: curve}, err
}

func PointLength(curve Curve, isCompressed bool) uint {
    // Returns the size (in bytes) of a compressed Point given a curve.
    // If no curve is provided, it returns 0.
    if curve.Group == nil {
        return 0
    }

    coordSize := curve.Size()

    if isCompressed {
        return 1 + coordSize
    } else {
        return 1 + 2 * coordSize
    }
}

func GenRandPoint(curve Curve) (Point, error) {
    // Returns a Point struct with a cryptographically
    // secure EC_POINT based on the provided curve.
    randPoint, err := GetNewECPoint(curve)
    if err != nil {
        return Point{}, err
    }

    randModBN, err := GenRandModBN(curve)
    if err != nil {
        return Point{}, err
    }
    defer randModBN.Free()

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(curve.Group, randPoint, (*C.BIGNUM)(C.NULL),
        curve.Generator, randModBN.Bignum, ctx)

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

    compressedSize := PointLength(curve, true)

    // Check if compressed
    if data[0] == 2 || data[0] == 3 {
        if uint(len(data)) != compressedSize {
            return Point{}, errors.New("X coordinate too large for curve")
        }

        // affineX might need to be freed.
        affineX := BytesToBN(data[1:])

        typeY := data[0] - 2

        point, err := GetNewECPoint(curve)
        if err != nil {
            return Point{}, err
        }

        ctx := C.BN_CTX_new()
        defer FreeBNCTX(ctx)

        result := C.EC_POINT_set_compressed_coordinates_GFp(
            curve.Group, point, affineX, C.int(typeY), ctx)
        if result != 1 {
            return Point{}, errors.New("Compressed deserialization failure")
        }
        return Point{point, curve}, nil
    } else if data[0] == 4 {
        // Handle uncompressed point
        coordSize := compressedSize - 1

        uncompressedSize := 1 + (2 * coordSize)

        if uint(len(data)) != uncompressedSize {
            return Point{}, errors.New("Uncompressed point does not have right size")
        }
        affineX := big.NewInt(0)
        affineY := big.NewInt(0)

        affineX.SetBytes(data[1:coordSize+1])
        affineY.SetBytes(data[1+coordSize:])

        return Affine2Point(affineX, affineY, curve)
    } else {
        return Point{}, errors.New("Invalid point serialization")
    }
}

func (m Point) ToBytes(isCompressed bool) ([]byte, error) {
    // Returns the Point serialized as bytes.
    // It will return a compressed form if isCompressed is set to True.
    x, y, err := m.ToAffine()
    if err != nil {
        return nil, err
    }

    if isCompressed {
        yBytes := y.Bytes()
        yBit := (yBytes[len(yBytes) - 1] & byte(1)) + 2

        var data []byte
        data = append(data, yBit)
        return append(data, x.Bytes()...), nil
    } else {
        var data []byte
        data = append(data, byte(4))
        data = append(data, x.Bytes()...)
        return append(data, y.Bytes()...), nil
    }
}

func GetPointFromGenerator(curve Curve) (ECPoint, Curve) {
    // Consider making a copy of this point
    // so there are not any double frees.
    return curve.Generator, curve
}

func (m Point) Equals(other Point) (bool, error) {
    if m.ECPoint == nil || other.ECPoint == nil {
        return false, errors.New("One of the EC_POINTs was null")
    }
    if m.Curve.Group == nil {
        return false, errors.New("The curve group is null")
    }

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

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_mul(m.Curve.Group, m.ECPoint, (*C.BIGNUM)(C.NULL),
        m.ECPoint, other.Bignum, ctx)
    if result != 1 {
        return errors.New("EC_POINT_mul failure")
    }

    return nil
}

func (m *Point) Add(other Point) error {
    // Performs an EC_POINT_add on two EC_POINTS.

    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_add(m.Curve.Group, m.ECPoint, m.ECPoint, other.ECPoint, ctx)
    if result != 1 {
        return errors.New("EC_POINT_add failure")
    }

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
    ctx := C.BN_CTX_new()
    defer FreeBNCTX(ctx)

    result := C.EC_POINT_invert(m.Curve.Group, m.ECPoint, ctx)
    if result != 1 {
        return errors.New("EC_POINT_invert failure")
    }

    return nil
}

func UnsafeHashToPoint() {
    // TODO: Hash arbitrary data into a valid EC point.
}

func (m Point) Copy() (Point, error) {
    // Deep copy of a Point EXCLUDING the curve.
    point := C.EC_POINT_dup(m.ECPoint, m.Curve.Group)
    if unsafe.Pointer(point) == C.NULL {
        return Point{}, errors.New("EC_POINT_dup failure")
    }

    return Point{ECPoint: point, Curve: m.Curve}, nil
}

func (m Point) Free() {
    FreeECPoint(m.ECPoint)
    // Do not free the curve.
    // m.Curve.Free()
}
