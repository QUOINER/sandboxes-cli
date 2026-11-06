//go:build darwin

package command

import "syscall"

// virtualizationSupport reports whether the host exposes a hypervisor.
func virtualizationSupport() (bool, string) {
	if data, err := syscall.Sysctl("kern.hv_support"); err == nil && data != "" && data[0] == 1 {
		return true, "kern.hv_support is 1"
	}
	return false, "kern.hv_support is not 1"
}
