// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && !ios

package cpu

import (
	"syscall"
	"unsafe"
	_ "unsafe"
) // for linkname

func sysctlEnabled(name []byte) bool {
	ret, value := sysctlbynameInt32(name)
	if ret < 0 {
		return false
	}
	return value > 0
}

// darwinKernelVersionCheck reports if Darwin kernel version is at
// least major.minor.patch.
//
// Code borrowed from x/sys/cpu.
func darwinKernelVersionCheck(major, minor, patch int) bool {
	var release [256]byte
	ret := sysctlbynameBytes([]byte("kern.osrelease\x00"), release[:])
	if ret < 0 {
		return false
	}

	var mmp [3]int
	c := 0
Loop:
	for _, b := range release[:] {
		switch {
		case b >= '0' && b <= '9':
			mmp[c] = 10*mmp[c] + int(b-'0')
		case b == '.':
			c++
			if c > 2 {
				return false
			}
		case b == 0:
			break Loop
		default:
			return false
		}
	}
	if c != 2 {
		return false
	}
	return mmp[0] > major || mmp[0] == major && (mmp[1] > minor || mmp[1] == minor && mmp[2] >= patch)
}

func sysctlbynameInt32(name []byte) (int32, int32) {
	out := int32(0)
	nout := unsafe.Sizeof(out)
	ret := sysctlbyname(&name[0], (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	return ret, out
}

func sysctlbynameBytes(name, out []byte) int32 {
	nout := uintptr(len(out))
	ret := sysctlbyname(&name[0], &out[0], &nout, nil, 0)
	return ret
}

func sysctlbyname(name *byte, oldp *byte, oldlenp *uintptr, newp *byte, newlen uintptr) int32 {
	_, _, r := syscall_syscall6(
		libc_sysctlbyname_trampoline_addr,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(oldp)),
		uintptr(unsafe.Pointer(oldlenp)),
		uintptr(unsafe.Pointer(newp)),
		uintptr(newlen),
		0,
	)

	return int32(r)
}

var libc_sysctlbyname_trampoline_addr uintptr

//go:cgo_import_dynamic libc_sysctlbyname sysctlbyname "/usr/lib/libSystem.B.dylib"

// from golang.org/x/sys@v0.30.0/unix/syscall_darwin_libSystem.go

// Implemented in the runtime package (runtime/sys_darwin.go)
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno) // 32-bit only
func syscall_rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func syscall_syscallPtr(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall syscall.syscall
//go:linkname syscall_syscall6 syscall.syscall6
//go:linkname syscall_syscall6X syscall.syscall6X
//go:linkname syscall_syscall9 syscall.syscall9
//go:linkname syscall_rawSyscall syscall.rawSyscall
//go:linkname syscall_rawSyscall6 syscall.rawSyscall6
//go:linkname syscall_syscallPtr syscall.syscallPtr
