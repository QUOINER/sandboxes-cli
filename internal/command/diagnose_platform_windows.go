//go:build windows

package command

import (
	"errors"
	"os/exec"
	"strings"
)

// virtualizationSupport defers to the WHPX backend checks on Windows.
func virtualizationSupport() (bool, string) {
	return false, ""
}

func checkDiskSpace(stateDir string) diagnoseCheck {
	check := diagnoseCheck{Name: "Disk space", Status: diagnoseSkip}
	check.Detail = "disk space check is not implemented on Windows"
	return check
}

func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func countHostProcesses() (daemons, shims int, err error) {
	return 0, 0, errors.New("host process scan is not implemented on Windows")
}

func containsRheicSSHConfig(data string) bool {
	return strings.Contains(data, "rsbx") || strings.Contains(data, "sandboxesd")
}
