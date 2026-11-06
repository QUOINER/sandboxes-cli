//go:build !windows

package command

import (
	"os/exec"
	"strings"
)

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
