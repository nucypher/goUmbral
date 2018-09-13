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

// #include "shim.h"
import "C"
import (
    "fmt"
)

const ERR_R_FATAL = 64

type OpenSSLError struct {
    code uint64
    library string
    function string
    reason string
    fatal bool
}

func (m *OpenSSLError) Error() string {
    if m.fatal {
        return fmt.Sprintf("OpenSSL FATAL Error: %x:%s:%s:%s",
            m.code, m.library, m.function, m.reason)
    } else {
        return fmt.Sprintf("OpenSSL NON_FATAL Error: %x:%s:%s:%s",
            m.code, m.library, m.function, m.reason)
    }
}

func NewOpenSSLError() *OpenSSLError {
    var code C.ulong = C.ERR_get_error()

    var library *C.char = C.ERR_lib_error_string(code)
    var function *C.char = C.ERR_func_error_string(code)
    var reason *C.char = C.ERR_reason_error_string(code)

    var goLib string = C.GoString(library)
    var goFun string = C.GoString(function)
    var goRea string = C.GoString(reason)

    fatal := code & ERR_R_FATAL

    return &OpenSSLError{uint64(code), goLib, goFun, goRea, fatal != 0}
}
