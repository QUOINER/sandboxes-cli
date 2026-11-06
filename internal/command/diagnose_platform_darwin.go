//go:build darwin

package command

import (
	"fmt"
	"syscall"
)

// checkDiskSpace reports free space on the state directory's volume.
func checkDiskSpace(stateDir string) diagnoseCheck {
	check := diagnoseCheck{Name: "Disk space"}
	if stateDir == "" {
		check.Status = diagnoseSkip
		check.Detail = "state directory is unknown"
		return check
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(stateDir, &stat); err != nil {
		check.Status = diagnoseWarn
		check.Detail = "cannot stat state directory: " + err.Error()
		return check
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	check.Status = diagnosePass
	check.Detail = fmt.Sprintf("%.1fGiB free on the state directory's volume", float64(freeBytes)/(1<<30))
	return check
}

// virtualizationSupport reports whether the host exposes a hypervisor.
func virtualizationSupport() (bool, string) {
	if data, err := syscall.Sysctl("kern.hv_support"); err == nil && data != "" && data[0] == 1 {
		return true, "kern.hv_support is 1"
	}
	return false, "kern.hv_support is not 1"
}
