//go:build linux && (arm || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || s390x)

package cpu

import (
	"os"
	"strings"
	"testing"
)

func TestAuxvValue(t *testing.T) {
	const _AT_PAGESZ = 6
	tests := []struct {
		name string
		auxv []uintptr
		tag  uintptr
		want uintptr
	}{
		{"first entry", []uintptr{_AT_HWCAP2, 2, _AT_HWCAP, 1, _AT_NULL, 0}, _AT_HWCAP2, 2},
		{"after other tag", []uintptr{_AT_HWCAP2, 2, _AT_HWCAP, 1, _AT_NULL, 0}, _AT_HWCAP, 1},
		{"value equal to tag", []uintptr{_AT_PAGESZ, _AT_HWCAP, _AT_HWCAP, 1}, _AT_HWCAP, 1},
		{"after AT_NULL", []uintptr{_AT_PAGESZ, 4096, _AT_NULL, 0, _AT_HWCAP, 1}, _AT_HWCAP, 0},
		{"truncated", []uintptr{_AT_PAGESZ, 4096, _AT_HWCAP}, _AT_HWCAP, 0},
	}
	for _, tt := range tests {
		if got := auxvValue(tt.auxv, tt.tag); got != tt.want {
			t.Errorf("%s: auxvValue(%v, %d) = %#x, want %#x", tt.name, tt.auxv, tt.tag, got, tt.want)
		}
	}
}

// TestHWCap checks HWCap against /proc/self/auxv, which is an independent
// source when the runtime provides the auxiliary vector (Go 1.21+).
func TestHWCap(t *testing.T) {
	a := readProcAuxv()
	if a == nil {
		t.Skip("/proc/self/auxv is not readable")
	}
	if want := uint(auxvValue(a, _AT_HWCAP)); HWCap != want {
		t.Errorf("HWCap = %#x, want AT_HWCAP %#x", HWCap, want)
	}
}

// TestHWCapBeforeDoinit checks that HWCap was set before init called doinit
// to derive the features from it.
func TestHWCapBeforeDoinit(t *testing.T) {
	if strings.Contains(os.Getenv("GODEBUG"), "cpu.") {
		t.Skip("GODEBUG may override features")
	}
	features := func() string {
		return marshal(ARM) + marshal(ARM64) + marshal(Loong64) + marshal(MIPS64X) + marshal(PPC64) + marshal(S390X)
	}
	before := features()
	doinit()
	if after := features(); after != before {
		t.Errorf("features derived at init differ from features derived from HWCap now:\ninit: %s\nnow:  %s", before, after)
	}
}
