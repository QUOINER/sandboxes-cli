package envfile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadMergesFilesAndDiscardsEnvironmentValues(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	secondDir := filepath.Join(dir, "second")
	if err := os.Mkdir(secondDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, first, "schemaVersion: \"1\"\nname: before\nagent: shell\nworkspace: work\nenv:\n  TOKEN: secret-one\n  SHARED: old\nsandboxOptions:\n  cpus: 2\n")
	writeEnvFile(t, filepath.Join(secondDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nname: after\nworkspace:\n  path: /tmp/override\nadditionalWorkspaces:\n  - path: data\n    readOnly: true\nenv:\n  SHARED: secret-two\n  SECOND: value\nsandboxOptions:\n  memory: 2g\n")

	plan, err := Load([]string{first, secondDir})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != "after" || plan.Agent != "shell" {
		t.Fatalf("unexpected merged identity: %#v", plan)
	}
	if plan.Workspace != "/tmp/override" {
		t.Fatalf("workspace = %q", plan.Workspace)
	}
	if len(plan.AdditionalWorkspaces) != 1 || plan.AdditionalWorkspaces[0] != (Workspace{Path: filepath.Join(secondDir, "data"), ReadOnly: true}) {
		t.Fatalf("additional workspaces = %#v", plan.AdditionalWorkspaces)
	}
	if !reflect.DeepEqual(plan.EnvironmentKeys, []string{"SECOND", "SHARED", "TOKEN"}) {
		t.Fatalf("environment keys = %#v", plan.EnvironmentKeys)
	}
	if plan.CPUs == nil || *plan.CPUs != 2 || plan.Memory != "2g" {
		t.Fatalf("resources = CPUs %v, memory %q", plan.CPUs, plan.Memory)
	}
}

func TestLoadRejectsUnsupportedFieldsAndMalformedDocuments(t *testing.T) {
	cases := map[string]string{
		"unknown field":           "schemaVersion: \"1\"\nagent: shell\nsecretSource: host\n",
		"nested unknown field":    "schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: work\n  writable: false\n",
		"second document":         "schemaVersion: \"1\"\nagent: shell\n---\nschemaVersion: \"1\"\nagent: shell\n",
		"missing agent":           "schemaVersion: \"1\"\nname: x\n",
		"invalid cpu":             "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  cpus: 0\n",
		"invalid memory":          "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  memory: 1k\n",
		"duplicate workspace key": "schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: a\n  path: b\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "env.yaml")
			writeEnvFile(t, path, body)
			if _, err := Load([]string{path}); err == nil {
				t.Fatal("Load() succeeded; want rejection")
			}
		})
	}
}

func TestLoadBoundsInputSizeAndRequiresExplicitPath(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Fatal("Load(nil) succeeded")
	}
	path := filepath.Join(t.TempDir(), "large.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\n"+strings.Repeat("#", maxFileSize))
	if _, err := Load([]string{path}); err == nil {
		t.Fatal("oversized input succeeded")
	}
}

func writeEnvFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
