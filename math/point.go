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
    "errors"
    "math"
    "math/big"
    "encoding/binary"
    "golang.org/x/crypto/blake2b"
    "github.com/nucypher/goUmbral/openssl"
)

// Represents an OpenSSL EC_POINT with a specific eliptic curve.

type Point struct {
   ECPoint openssl.ECPoint
   Curve *openssl.Curve
}

// Generate a new Point struct based on the arguments provided.
//
// If point is nil then GetNewPoint will generate a new opensslraphically secure
// ECPoint and check for errors before returning the new Point.
//
// if point is nil AND the curve group is also nil then
// GetNewPoint will fail and return the error.
func NewPoint(point openssl.ECPoint, curve *openssl.Curve) (*Point, error) {
    var err error = nil
    if point == nil {
        newPoint, err := GenRandPoint(curve)
        if err != nil {
            return nil, err
        }
        return newPoint, err
    }
    return &Point{point, curve}, err
}

// Returns the size (in bytes) of a compressed Point given a curve.
// If no curve is provided, it returns 0.
func PointLength(curve *openssl.Curve, isCompressed bool) uint {
    if curve.Group == nil {
        return 0
    }

    coordSize := curve.FieldOrderSize()

    if isCompressed {
        return 1 + coordSize
    } else {
        return 1 + 2 * coordSize
    }
}

// Returns a Point struct with a cryptographically
// secure EC_POINT based on the provided curve.
func GenRandPoint(curve *openssl.Curve) (*Point, error) {
    randPoint, err := openssl.NewECPoint(curve)
    if err != nil {
        return nil, err
    }

    randModBN, err := GenRandModBN(curve)
    if err != nil {
        return nil, err
    }
    defer randModBN.Free()

    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    result := openssl.MulECP(curve.Group, randPoint, nil,
        curve.Generator, randModBN.Bignum, ctx)
    if result != nil {
        return nil, result
    }

    return &Point{randPoint, curve}, nil
}

// Returns a Point object from the given affine coordinates.
func AffineToPoint(affineX, affineY *big.Int, curve *openssl.Curve) (*Point, error) {
    x, err := openssl.BigIntToBN(affineX)
    if err != nil {
        return nil, err
    }
    y, err := openssl.BigIntToBN(affineY)
    if err != nil {
        return nil, err
    }

    point, err := openssl.GetECPointFromAffine(x, y, curve)
    if err != nil {
        return nil, err
    }

    return &Point{point, curve}, nil
}

// Returns an x and y coordinate of the Point as a Go big.Int.
func (m Point) ToAffine() (*big.Int, *big.Int, error) {
    xBN, yBN, err := openssl.GetAffineCoordsFromECPoint(m.ECPoint, m.Curve)
    if err != nil {
        return nil, nil, err
    }
    defer openssl.FreeBigNum(xBN)
    defer openssl.FreeBigNum(yBN)

    goX, err := openssl.BNToBigInt(xBN)
    if err != nil {
        return nil, nil, err
    }
    goY, err := openssl.BNToBigInt(yBN)
    if err != nil {
        return nil, nil, err
    }
    return goX, goY, nil
}

func BytesToPoint(data []byte, curve *openssl.Curve) (*Point, error) {
    if len(data) == 0 {
        return nil, errors.New("No bytes failure")
    }

    compressedSize := PointLength(curve, true)

    // Check if compressed
    if data[0] == 2 || data[0] == 3 {
        if uint(len(data)) != compressedSize {
            return nil, errors.New("X coordinate too large for curve")
        }

        // affineX might need to be freed.
        affineX, err := openssl.BytesToBN(data[1:])
        if err != nil {
            return nil, err
        }

        typeY := data[0] - 2

        point, err := openssl.NewECPoint(curve)
        if err != nil {
            return nil, err
        }

        ctx := openssl.NewBNCtx()
        defer openssl.FreeBNCtx(ctx)

        result := openssl.SetCompressedCoordsECP(
            curve.Group, point, affineX, int(typeY), ctx)
        if result != nil {
            return nil, result
        }
        return &Point{point, curve}, nil
    } else if data[0] == 4 {
        // Handle uncompressed point
        coordSize := compressedSize - 1

        uncompressedSize := 1 + (2 * coordSize)

        if uint(len(data)) != uncompressedSize {
            return nil, errors.New("Uncompressed point does not have right size")
        }
        affineX := big.NewInt(0)
        affineY := big.NewInt(0)

        affineX.SetBytes(data[1:coordSize+1])
        affineY.SetBytes(data[1+coordSize:])

        return AffineToPoint(affineX, affineY, curve)
    } else {
        return nil, errors.New("Invalid point serialization")
    }
}

// Returns the Point serialized as bytes.
// It will return a compressed form if isCompressed is set to True.
func (m Point) ToBytes(isCompressed bool) ([]byte, error) {
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

func GetGeneratorFromCurve(curve *openssl.Curve) *Point {
    // Consider making a copy of this point
    // so there are not any double frees.
    return &Point{curve.Generator, curve}
}

func (m *Point) Equals(other *Point) (bool, error) {
    if m.ECPoint == nil || other.ECPoint == nil {
        return false, errors.New("One of the EC_POINTs was null")
    }
    if m.Curve.Group == nil {
        return false, errors.New("The curve group is null")
    }

    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    result, err := openssl.CmpECP(m.Curve.Group, m.ECPoint, other.ECPoint, ctx)
    if err != nil {
        return false, err
    }
    return result, nil
}

// Point.Mul() will perform (x * y).
// It will then set z to the result of that operation.
//
// x, y, and z must use the same curve and must be initialized.
//
// Mul will return the error if one occurred, and nil otherwise.
func (z *Point) Mul(x *Point, y *ModBigNum) error {
    if !x.Curve.Equals(y.Curve) {
        return errors.New("The points do not share the same curve.")
    }

    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    result := openssl.MulECP(x.Curve.Group, z.ECPoint, nil,
        x.ECPoint, y.Bignum, ctx)
    if result != nil {
        return result
    }
    return nil
}

// Point.Add() will perform (x + y).
// It will then set z to the result of that operation.
//
// x, y, and z must use the same curve and must be initialized.
//
// Add will return the error if one occurred, and nil otherwise.
func (z *Point) Add(x, y *Point) error {
    if !x.Curve.Equals(y.Curve) {
        return errors.New("The points do not share the same curve.")
    }

    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    result := openssl.AddECP(x.Curve.Group, z.ECPoint, x.ECPoint, y.ECPoint, ctx)
    if result != nil {
        return result
    }

    return nil
}

// Point.Sub() will perform (x - y).
// It will then set z to the result of that operation.
//
// x, y, and z must use the same curve and must be initialized.
//
// Sub will return the error if one occurred, and nil otherwise.
func (z *Point) Sub(x, y *Point) error {
    if !x.Curve.Equals(y.Curve) {
        return errors.New("The points do not share the same curve.")
    }

    // Performs a subtraction on two EC_POINTS by adding by the inverse.
    inv, err := y.Copy()
    if err != nil {
        return err
    }
    defer inv.Free()

    err = inv.Invert(y)
    if err != nil {
        return err
    }

    err = z.Add(x, inv)
    if err != nil {
        return err
    }

    return nil
}

// Point.Invert() will find the inverse of x.
// It will then set z to the result of that operation.
//
// x must be initialized.
//
// Invert will return the error if one occurred, and nil otherwise.
func (z *Point) Invert(x *Point) error {
    ctx := openssl.NewBNCtx()
    defer openssl.FreeBNCtx(ctx)

    inv, err := x.Copy()
    if err != nil {
        return err
    }

    result := openssl.InvertECP(x.Curve.Group, inv.ECPoint, ctx)
    if result != nil {
        return result
    }
    if z.ECPoint != nil {
        openssl.FreeECPoint(z.ECPoint)
    }
    z.ECPoint = inv.ECPoint

    return nil
}

// Hashes arbitrary data into a valid EC point of the specified curve,
// using the try-and-increment method.
// It admits an optional label as an additional input to the hash function.
// It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.

// WARNING: Do not use when the input data is secret, as this implementation is not
// in constant time, and hence, it is not safe with respect to timing attacks.
// TODO: Check how to uniformly generate ycoords. Currently, it only outputs points
// where ycoord is even (i.e., starting with 0x02 in compressed notation)
func UnsafeHashToPoint(data []byte, params *UmbralParameters, label []byte) (*Point, error) {
    max := uint32(math.Exp2(32) - 1)

    lenData := make([]byte, 4)
    lenLabel := make([]byte, 4)

    binary.BigEndian.PutUint32(lenLabel, uint32(len(label)))
    binary.BigEndian.PutUint32(lenData, uint32(len(data)))

    labelData := append(lenLabel, label...)
    labelData = append(labelData, lenData...)
    labelData = append(labelData, data...)

    bs := make([]byte, 4)

    // We use an internal 32-bit counter as additional input
    for i := uint32(0); i < max; i++ {
        binary.BigEndian.PutUint32(bs, i)

        dataCopy := make([]byte, len(labelData))
        copy(dataCopy, labelData)

        dataCopy = append(dataCopy, bs...)

        hash := blake2b.Sum512(dataCopy)

        var sign []byte = make([]byte, 1)
        if hash[0] & 1 == 0 {
            sign[0] = byte(2)
        } else {
            sign[0] = byte(3)
        }

        compressedPoint := append(sign, hash[1:1 + params.Size]...)

        point, err := BytesToPoint(compressedPoint, params.Curve)

        if err != nil {
            // TODO: Catching Exceptions
            // We want to catch specific InternalExceptions:
            // - Point not in the curve (code 107)
            // - Invalid compressed point (code 110)
            // https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
            // return Point{}, err
            continue
        } else {
            return point, nil
        }
    }

    // Only happens with probability 2^(-32)
    return nil, errors.New("Could not hash input into the curve")
}

func (m *Point) Copy() (*Point, error) {
    // Deep copy of a Point EXCLUDING the curve.
    point, err := openssl.DupECP(m.ECPoint, m.Curve.Group)
    if err != nil {
        return nil, err
    }

    return &Point{point, m.Curve}, nil
}

func (m *Point) Free() {
    openssl.FreeECPoint(m.ECPoint)
    // Do not free the curve.
    // m.Curve.Free()
}
