//go:build linux && (arm || ppc64 || ppc64le)

package cpu

// See hwcap_linux.go.
var _ = setFromAuxv(&HWCap2, _AT_HWCAP2)
