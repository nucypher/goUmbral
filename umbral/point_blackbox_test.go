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
package umbral_test

import (
    "testing"
    "encoding/json"
    "encoding/hex"
    "io/ioutil"
    "github.com/nucypher/goUmbral/umbral"
)

type PointOps struct {
    Name string `json:"name"`
    Params string `json:"params"`
    FirstOp string `json:"first Point operand"`
    SecondOp string `json:"second Point operand"`
    CurveBNOp string `json:"CurveBN operand"`
    Vectors []Vector `json:"vectors"`
}

type Vector struct{
    Op string `json:"operation"`
    Result string `json:"result"`
}

func TestPointOperations(t *testing.T) {
    data, err := ioutil.ReadFile("../vectors/vectors_point_operations.json")
    if err != nil {
        t.Error(err)
    }

    var pops PointOps
    err = json.Unmarshal(data, &pops)

    if err != nil {
        t.Error(err)
    }

    curve, err := umbral.GetNewCurve(umbral.SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    first, err := hex.DecodeString(pops.FirstOp)
    if err != nil {
        t.Error(err)
    }

    second, err := hex.DecodeString(pops.SecondOp)
    if err != nil {
        t.Error(err)
    }

    third, err := hex.DecodeString(pops.CurveBNOp)
    if err != nil {
        t.Error(err)
    }

    point1, err := umbral.Bytes2Point(first, curve)
    if err != nil {
        t.Error(err)
    }
    defer point1.Free()

    point2, err := umbral.Bytes2Point(second, curve)
    if err != nil {
        t.Error(err)
    }
    defer point2.Free()

    modbn, err := umbral.Bytes2ModBN(third, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn.Free()

    for _, k := range pops.Vectors {
        tmp1, err := point1.Copy()
        if err != nil {
            t.Error(err)
        }

        tmp2, err := point2.Copy()
        if err != nil {
            t.Error(err)
        }

        tmp4, err := modbn.Copy()
        if err != nil {
            t.Error(err)
        }

        switch k.Op {
        case "Addition":
            err = tmp1.Add(tmp2)
            if err != nil {
                t.Error(err)
            }
            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            point3, err := umbral.Bytes2Point(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer point3.Free()

            equ, err := tmp1.Equals(point3)
            if err != nil {
                t.Error(err)
            }

            if !equ {
                t.Error("After adding, the points were not equal")
            }
        case "Subtraction":
            err = tmp1.Sub(tmp2)
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            point3, err := umbral.Bytes2Point(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer point3.Free()

            equ, err := tmp1.Equals(point3)
            if err != nil {
                t.Error(err)
            }

            if !equ {
                t.Error("After subtraction, the points were not equal")
            }
        case "Multiplication":
            err = tmp1.Mul(tmp4)
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            point3, err := umbral.Bytes2Point(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer point3.Free()

            equ, err := tmp1.Equals(point3)
            if err != nil {
                t.Error(err)
            }

            if !equ {
                t.Error("After multiplication, the points were not equal")
            }
        case "Inversion":
            err = tmp1.Invert()
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            point3, err := umbral.Bytes2Point(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer point3.Free()

            equ, err := tmp1.Equals(point3)
            if err != nil {
                t.Error(err)
            }

            if !equ {
                t.Error("After inverting, the points were not equal")
            }
        case "To_affine.X":
            x, _, err := tmp1.ToAffine()
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            xRes := umbral.BytesToBigInt(tmp3)

            res := x.Cmp(xRes)
            if res != 0 {
                t.Error("Affine x was not equal.")
            }
        case "To_affine.Y":
            _, y, err := tmp1.ToAffine()
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            yRes := umbral.BytesToBigInt(tmp3)

            res := y.Cmp(yRes)
            if res != 0 {
                t.Error("Affine y was not equal.")
            }
        default:
        }
        tmp1.Free()
        tmp2.Free()
    }
}
