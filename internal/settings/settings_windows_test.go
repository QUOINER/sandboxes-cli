//go:build windows

package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFailsClosedWithoutWindowsACLValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte("default_cpus = 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("Load error = %v; expected fail-closed ACL rejection", err)
	}
}
