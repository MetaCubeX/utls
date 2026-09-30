//go:build linux && (arm || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || s390x)

package cpu

import (
	"os"
	"unsafe"
)

// Auxiliary vector tags, see getauxval(3).
const (
	_AT_NULL   = 0
	_AT_HWCAP  = 16
	_AT_HWCAP2 = 26
)

// In internal/cpu, HWCap and HWCap2 are filled in by the runtime from the
// auxiliary vector before initialization. The runtime does not know about
// this copy of the package, so fill them in here, unless they are already
// set. Package-level variables are initialized before init calls doinit.
var _ = setFromAuxv(&HWCap, _AT_HWCAP)

// auxv is the auxiliary vector as (tag, value) pairs, or nil if unavailable.
var auxv = getAuxv()

// setFromAuxv sets *v to the value of the auxiliary vector entry tag unless
// *v is already set. It returns a value only to be usable in var declarations.
func setFromAuxv(v *uint, tag uintptr) bool {
	if *v == 0 {
		*v = uint(auxvValue(auxv, tag))
	}
	return true
}

func getAuxv() []uintptr {
	if a := runtime_getAuxv(); len(a) > 0 {
		return a
	}
	return readProcAuxv()
}

// readProcAuxv reads the auxiliary vector from /proc/self/auxv. That file is
// not readable by processes that are not dumpable, e.g. binaries with file
// capabilities, which is why getAuxv prefers the runtime's copy.
func readProcAuxv() []uintptr {
	buf, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil
	}
	// The file holds words of the native size and byte order.
	const wordSize = int(unsafe.Sizeof(uintptr(0)))
	a := make([]uintptr, len(buf)/wordSize)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(a))), len(a)*wordSize), buf)
	return a
}

// auxvValue returns the value of the first entry with the given tag in a,
// or 0 if there is no such entry before the AT_NULL entry ending the vector.
func auxvValue(a []uintptr, tag uintptr) uintptr {
	for ; len(a) >= 2 && a[0] != _AT_NULL; a = a[2:] {
		if a[0] == tag {
			return a[1]
		}
	}
	return 0
}
