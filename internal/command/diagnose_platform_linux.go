//go:build linux

package command

import "os"

// virtualizationSupport reports whether the host exposes a hypervisor.
func virtualizationSupport() (bool, string) {
	if _, err := os.Stat("/dev/kvm"); err == nil {
		return true, "/dev/kvm is present"
	}
	return false, "/dev/kvm is absent"
}
