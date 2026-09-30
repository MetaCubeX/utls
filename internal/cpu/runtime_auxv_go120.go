//go:build linux && !go1.21

package cpu

// runtime.getAuxv does not exist before Go 1.21, so getAuxv falls back to
// reading /proc/self/auxv.
func runtime_getAuxv() []uintptr { return nil }
