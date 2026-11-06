//go:build !windows

package command

import (
	"fmt"
	"os/exec"
	"strings"
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
	//nolint:gosec // statfs block size is always positive.
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	check.Status = diagnosePass
	check.Detail = formatGiB(freeBytes) + " free on the state directory's volume"
	return check
}

func formatGiB(bytes uint64) string {
	return fmt.Sprintf("%.1fGiB", float64(bytes)/(1<<30))
}

func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// countHostProcesses uses pgrep when available so tests stay hermetic and no
// process state is required for a skip.
func countHostProcesses() (daemons, shims int, err error) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		return 0, 0, err
	}
	count := func(pattern string) int {
		// #nosec G204 -- fixed pgrep argv, read-only host diagnostic.
		output, runErr := exec.Command("pgrep", "-f", pattern).Output()
		if runErr != nil {
			return 0
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			return 0
		}
		return len(lines)
	}
	return count("rheicd"), count("containerd-shim-nerdbox-v1"), nil
}

func containsRheicSSHConfig(data string) bool {
	return strings.Contains(data, "rsbx") || strings.Contains(data, "sandboxesd")
}
