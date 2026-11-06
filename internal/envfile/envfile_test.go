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
	writeEnvFile(t, filepath.Join(secondDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nname: after\nworkspace:\n  path: override\nadditionalWorkspaces:\n  - path: data\n    readOnly: true\nenv:\n  SHARED: secret-two\n  SECOND: value\nsandboxOptions:\n  memory: 2g\n")

	plan, err := Load([]string{first, secondDir})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != "after" || plan.Agent != "shell" {
		t.Fatalf("unexpected merged identity: %#v", plan)
	}
	if plan.Workspace != filepath.Join(secondDir, "override") {
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

func TestDecodeDocumentRejectsAliasesAndDeepNesting(t *testing.T) {
	alias := []byte("schemaVersion: \"1\"\nagent: &agent shell\nname: *agent\n")
	if _, err := decodeDocument(alias); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("alias input error = %v, want alias rejection", err)
	}
	deep := "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  nested: " + strings.Repeat("[", maxYAMLDepth) + "x" + strings.Repeat("]", maxYAMLDepth) + "\n"
	if _, err := decodeDocument([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep input error = %v, want nesting rejection", err)
	}
}

func FuzzDecodeDocument(f *testing.F) {
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\nenv:\n  API_TOKEN: secret\n"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: work\n"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\n---\nsecond: document\n"))
	f.Add([]byte("{invalid yaml"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: &agent shell\nname: *agent\n"))
	f.Add([]byte(strings.Repeat("x", maxFileSize+1)))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := decodeDocument(data)
		if err == nil {
			_ = doc.validate()
		}
	})
}

func writeEnvFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
