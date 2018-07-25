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

type ModBNOps struct {
    Name string `json:"name"`
    Params string `json:"params"`
    FirstOp string `json:"first operand"`
    SecondOp string `json:"second operand"`
    Vectors []Vector `json:"vectors"`
}

type HashOps struct {
    Name string `json:"name"`
    Params string `json:"params"`
    Vectors []HVector `json:"vectors"`
}

type HVector struct{
    Input []Input `json:"input"`
    Output string `json:"output"`
}

type Input struct {
    Class string `json:"class"`
    Bytes string `json:"bytes"`
}

func TestModBNOperations(t *testing.T) {
    data, err := ioutil.ReadFile("../vectors/vectors_curvebn_operations.json")
    if err != nil {
        t.Error(err)
    }

    var pops ModBNOps
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

    modbn1, err := umbral.Bytes2ModBN(first, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn1.Free()

    modbn2, err := umbral.Bytes2ModBN(second, curve)
    if err != nil {
        t.Error(err)
    }
    defer modbn2.Free()

    for _, k := range pops.Vectors {
        tmp1, err := modbn1.Copy()
        if err != nil {
            t.Error(err)
        }

        tmp2, err := modbn2.Copy()
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

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After adding, the modbns were not equal")
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

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After subtraction, the modbns were not equal")
            }
        case "Multiplication":
            err = tmp1.Mul(tmp2)
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After multiplication, the modbns were not equal")
            }
        case "Division":
            err = tmp1.Div(tmp2)
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After division, the modbns were not equal")
            }
        case "Pow":
            err = tmp1.Pow(tmp2)
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After exponentiating, the modbns were not equal")
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

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After inverting, the modbns were not equal")
            }
        case "Neg":
            err = tmp1.Neg()
            if err != nil {
                t.Error(err)
            }

            tmp3, err := hex.DecodeString(k.Result)
            if err != nil {
                t.Error(err)
            }

            modbn3, err := umbral.Bytes2ModBN(tmp3, curve)
            if err != nil {
                t.Error(err)
            }
            defer modbn3.Free()

            if !tmp1.Equals(modbn3) {
                t.Error("After negating, the modbns were not equal")
            }
        default:
        }
        tmp1.Free()
        tmp2.Free()
    }
}

func TestHash2ModBN(t *testing.T) {
    data, err := ioutil.ReadFile("../vectors/vectors_curvebn_hash.json")
    if err != nil {
        t.Error(err)
    }

    var pops HashOps
    err = json.Unmarshal(data, &pops)
    if err != nil {
        t.Error(err)
    }

    curve, err := umbral.GetNewCurve(umbral.SECP256K1)
    if err != nil {
        t.Error(err)
    }
    defer curve.Free()

    params, err := umbral.GetNewUmbralParameters(curve)
    if err != nil {
        t.Error(err)
    }

    for _, k := range pops.Vectors {
        var data []byte
        for _, m := range k.Input {
            bytes, err := hex.DecodeString(m.Bytes)
            if err != nil {
                t.Error(err)
            }
            data = append(data, bytes...)
        }

        modbn1, err := umbral.Hash2ModBN(data, params)
        if err != nil {
            t.Error(err)
        }
        defer modbn1.Free()

        tmp1, err := hex.DecodeString(k.Output)
        if err != nil {
            t.Error(err)
        }

        modbn2, err := umbral.Bytes2ModBN(tmp1, curve)
        if err != nil {
            t.Error(err)
        }
        defer modbn2.Free()

        if !modbn1.Equals(modbn2) {
            t.Error("After hashing:", k, ", the points were not equal")
        }
    }
}
