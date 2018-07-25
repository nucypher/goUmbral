package umbral

// #include "shim.h"
import "C"

type UmbralParameters struct {
    Curve Curve
    Size uint
    G Point
    U Point
}

func GetNewUmbralParameters(curve Curve) (UmbralParameters, error) {
    var params UmbralParameters
    params.Curve = curve
    params.Size = curve.FieldOrderSize()

    params.G = GetGeneratorFromCurve(curve)
    gBytes, err := params.G.ToBytes(true)
    if err != nil {
        return UmbralParameters{}, err
    }

    parametersSeed := []byte("NuCypher/UmbralParameters/")

    parametersSeed = append(parametersSeed, byte('u'))

    params.U, err = UnsafeHashToPoint(gBytes, params, parametersSeed)
    if err != nil {
        return UmbralParameters{}, err
    }
    return params, nil
}

func (m UmbralParameters) Equals(other UmbralParameters) bool {
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
