//go:build !windows

package system

import "syscall"

func getDiskStats(path string) (total uint64, used uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	if total >= free {
		used = total - free
	}
	return total, used, nil
}
