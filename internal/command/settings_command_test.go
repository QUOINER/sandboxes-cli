package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func runSettings(t *testing.T, envPath string, args ...string) (*bytes.Buffer, int) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: filepath.Join(t.TempDir(), "sandboxesd.sock"),
		NewClient: func(string) (sdk.Client, error) { return nil, errors.New("settings does not need a daemon") }}
	t.Setenv("RHEIC_SETTINGS_FILE", envPath)
	return &out, runner.Run(context.Background(), append([]string{"settings"}, args...))
}

func TestSettingsListsFullCatalogWithDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "ls", "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var rows []settingOutput
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json: %v output=%q", err, out.String())
	}
	if len(rows) != 53 {
		t.Fatalf("rows=%d, want 53", len(rows))
	}
	byKey := map[string]settingOutput{}
	for _, row := range rows {
		byKey[row.Key] = row
	}
	if row := byKey["proxy.daemon"]; row.Source != "default" || row.Value != "" || !row.Restart {
		t.Fatalf("proxy.daemon row = %+v", row)
	}
	if row := byKey["kit.requireSignature"]; row.Type != "bool" || row.Default != "false" {
		t.Fatalf("kit.requireSignature row = %+v", row)
	}
	if row := byKey["sandbox.disk.dockerVolume"]; row.Default != "10g" {
		t.Fatalf("docker volume row = %+v", row)
	}
}

func TestSettingsSetValidatesCatalogTypesAndPersistsExtras(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "set", "ssh.autoCreate", "true")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	out, code = runSettings(t, path, "set", "kit.allowedSources", `["registry.example/"]`)
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if _, code := runSettings(t, path, "set", "ssh.autoCreate", "yes"); code == 0 {
		t.Fatal("invalid bool accepted")
	}
	if _, code := runSettings(t, path, "set", "no.such.key", "x"); code == 0 {
		t.Fatal("unknown key accepted")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned settings file.
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `ssh.autoCreate = "true"`) || !strings.Contains(text, `kit.allowedSources = "[\"registry.example/\"]"`) {
		t.Fatalf("file=%q", text)
	}
	out, code = runSettings(t, path, "get", "ssh.autoCreate")
	if code != 0 || strings.TrimSpace(out.String()) != "true" {
		t.Fatalf("get exit=%d output=%q", code, out.String())
	}
	if _, code := runSettings(t, path, "unset", "ssh.autoCreate"); code != 0 {
		t.Fatalf("unset exit=%d", code)
	}
	out, code = runSettings(t, path, "get", "ssh.autoCreate", "--json")
	if code != 0 || !strings.Contains(out.String(), `"source": "default"`) {
		t.Fatalf("get --json exit=%d output=%q", code, out.String())
	}
}

func TestSettingsMarksRestartRequiredKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "set", "proxy.daemon", "http://proxy.example:3128")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "restart rheicd to apply proxy.daemon") {
		t.Fatalf("restart notice missing: %q", out.String())
	}
}
