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
package openssl

import (
    "testing"
)

func TestError(t *testing.T) {
    bn1, err := IntToBN(0)
    if err != nil {
        t.Error(err)
    }
    bn2, err := IntToBN(5)
    if err != nil {
        t.Error(err)
    }

    bn3 := NewBigNum()

    err = SubBN(bn3, bn1, bn2)
    if err != nil {
        t.Log(err)
    }

    bn4 := NewBigNum()

    err = RandRangeBN(bn4, bn3)
    if err == nil {
        t.Error("Should have returned error: 'OpenSSL FATAL Error: 307a073:bignum routines:BN_rand_range:invalid range'")
    }
}
