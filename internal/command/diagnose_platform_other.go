//go:build !darwin && !linux && !windows

package command

// virtualizationSupport is unknown on unqualified platforms.
func virtualizationSupport() (bool, string) {
	return false, ""
}
