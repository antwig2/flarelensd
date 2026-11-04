//go:build windows

package system

import (
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func getDiskStats(path string) (total uint64, used uint64, err error) {
	if path == "" || path == "/" {
		path = "C:\\"
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}

	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64

	r1, _, errCall := procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		return 0, 0, errCall
	}

	total = totalNumberOfBytes
	if total >= totalNumberOfFreeBytes {
		used = total - totalNumberOfFreeBytes
	}
	return total, used, nil
}
