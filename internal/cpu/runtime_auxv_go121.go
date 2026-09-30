//go:build linux && go1.21

package cpu

import _ "unsafe" // for linkname

// runtime_getAuxv returns the auxiliary vector saved by the runtime at startup.
// runtime.getAuxv exists since Go 1.21 and is kept for linkname use by
// golang.org/x/sys/cpu, see go.dev/issue/57336 and go.dev/issue/67401.
//
//go:linkname runtime_getAuxv runtime.getAuxv
func runtime_getAuxv() []uintptr
