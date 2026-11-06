//go:build !darwin && !linux && !windows

package command

// virtualizationSupport is unknown on unqualified platforms.
func virtualizationSupport() (bool, string) {
	return false, ""
}

func checkDiskSpace(string) diagnoseCheck {
	return diagnoseCheck{Name: "Disk space", Status: diagnoseSkip, Detail: "disk space check is not implemented on this platform"}
}
