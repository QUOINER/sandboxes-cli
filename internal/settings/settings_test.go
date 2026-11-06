package settings

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL validation is not implemented; Load remains fail closed")
	}
	path := filepath.Join(t.TempDir(), "rheic", "settings.toml")
	want := Values{DNSUpstream: "1.1.1.1:53", DefaultPolicyProfile: "balanced", DefaultCPUs: 4, DefaultMemoryMiB: 2048, DockerVolumeSize: "20g"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.DNSUpstream != want.DNSUpstream || got.DefaultPolicyProfile != want.DefaultPolicyProfile ||
		got.DefaultCPUs != want.DefaultCPUs || got.DefaultMemoryMiB != want.DefaultMemoryMiB || got.DockerVolumeSize != want.DockerVolumeSize {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := Save(path, Values{DNSUpstream: "1.1.1.1:53"}); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil || got.DNSUpstream != "1.1.1.1:53" || got.DefaultCPUs != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestLoadRejectsUnknownAndUnsafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL validation is not implemented; see Windows fail-closed test")
	}
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte("nope = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err=%v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("err=%v", err)
	}
}

func TestCatalogCoversDockerMatrixAndValidatesTypes(t *testing.T) {
	if got := len(Catalog()); got != 53 {
		t.Fatalf("catalog entries = %d, want 53 (49 Docker keys + 4 Rheic extensions)", got)
	}
	entry, found := Find("proxy.daemon")
	if !found || entry.Type != "string" || !entry.Restart {
		t.Fatalf("proxy.daemon entry = %+v found=%v", entry, found)
	}
	entry, found = Find("kit.allowedSources")
	if !found || entry.Type != "json" || entry.Default != `["docker.io/"]` {
		t.Fatalf("kit.allowedSources entry = %+v found=%v", entry, found)
	}
	if err := ValidateValue(entry, `["registry.example/"]`); err != nil {
		t.Fatalf("valid JSON rejected: %v", err)
	}
	if err := ValidateValue(entry, "not json"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if err := ValidateValue(FindEntry(t, "ssh.autoCreate"), "true"); err != nil {
		t.Fatalf("valid bool rejected: %v", err)
	}
	if err := ValidateValue(FindEntry(t, "ssh.autoCreate"), "yes"); err == nil {
		t.Fatal("invalid bool accepted")
	}
	if err := ValidateValue(FindEntry(t, "daemon.log.maxAgeDays"), "4000"); err == nil {
		t.Fatal("maxAgeDays above 3650 accepted")
	}
	if err := ValidateValue(FindEntry(t, "daemon.log.maxSizeMB"), "100"); err != nil {
		t.Fatalf("valid int rejected: %v", err)
	}
	if _, found := Find("no.such.key"); found {
		t.Fatal("unknown key found in catalog")
	}
}

func TestExtraOverridesRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL validation is not implemented; Load remains fail closed")
	}
	path := filepath.Join(t.TempDir(), "settings.toml")
	values := Values{Extra: map[string]string{"proxy.daemon": "http://proxy.example:3128", "kit.requireSignature": "true"}}
	if err := Save(path, values); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Extra["proxy.daemon"] != "http://proxy.example:3128" || got.Extra["kit.requireSignature"] != "true" {
		t.Fatalf("extra=%+v", got.Extra)
	}
}

func FindEntry(t *testing.T, key string) Entry {
	t.Helper()
	entry, found := Find(key)
	if !found {
		t.Fatalf("key %q not in catalog", key)
	}
	return entry
}
