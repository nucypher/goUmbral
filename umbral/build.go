package umbral

// #cgo CFLAGS: -I${SRCDIR}/../libs/boringssl/include
// #cgo LDFLAGS: -L/usr/lib/crypto -lcrypto
import "C"

// -L/usr/lib/crypto WORKING
// -L${SRCDIR}/../../boringssl/build/crypto NOT WORKING
// -L${SRCDIR}/../libs/boringssl WORKING
// -lpthread MAYBE
