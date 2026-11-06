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
	writeEnvFile(t, first, "schemaVersion: \"1\"\nname: before\nagent: shell\nworkspace: work\nports:\n  - sandbox: 3000\n    host: 4300\n    protocol: tcp\nenv:\n  TOKEN: secret-one\n  SHARED: old\nsandboxOptions:\n  cpus: 2\n")
	writeEnvFile(t, filepath.Join(secondDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nname: after\nworkspace:\n  path: override\nadditionalWorkspaces:\n  - path: data\n    readOnly: true\nports:\n  - sandbox: 9222\n    hostIP: 127.0.0.1\nenv:\n  SHARED: secret-two\n  SECOND: value\nsandboxOptions:\n  memory: 2g\n")

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
	if len(plan.Ports) != 2 || plan.Ports[0].Sandbox != 3000 || plan.Ports[0].Host == nil || *plan.Ports[0].Host != 4300 || plan.Ports[0].Protocol != "tcp" || plan.Ports[1].Sandbox != 9222 || plan.Ports[1].Host != nil || plan.Ports[1].HostIP != "127.0.0.1" {
		t.Fatalf("ports = %#v", plan.Ports)
	}
}

func TestLoadDefaultMergesUserDefaultsBeforeCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(homeDir, ".sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nname: shared\nworkspace: shared-work\nenv:\n  SHARED: hidden\n")
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nname: project\nworkspace: project-work\nenv:\n  PROJECT: hidden\n")

	plan, err := LoadDefault(homeDir, workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != "project" || plan.Workspace != filepath.Join(workingDir, "project-work") {
		t.Fatalf("project values did not override defaults: %#v", plan)
	}
	if !reflect.DeepEqual(plan.EnvironmentKeys, []string{"PROJECT", "SHARED"}) {
		t.Fatalf("merged environment keys = %#v", plan.EnvironmentKeys)
	}

	explicit, err := Load([]string{workingDir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(explicit.EnvironmentKeys, []string{"PROJECT"}) {
		t.Fatalf("explicit path unexpectedly included user defaults: %#v", explicit.EnvironmentKeys)
	}
}

func TestLoadDefaultAllowsMissingUserDefaultsButRequiresProjectFile(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\n")
	if _, err := LoadDefault(homeDir, workingDir); err != nil {
		t.Fatalf("missing optional home defaults rejected: %v", err)
	}
	if _, err := LoadDefault(homeDir, root); err == nil {
		t.Fatal("missing working-directory environment file accepted")
	}
}

func TestLoadExpandsProjectAndFileDirectoryReferences(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	baseDir := filepath.Join(root, "defaults")
	if err := os.Mkdir(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(baseDir, "base.yaml")
	project := filepath.Join(projectDir, "sbxenv.yaml")
	writeEnvFile(t, base, "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}/base\"\nadditionalWorkspaces:\n  - path: \"${{ env.fileDir }}/shared\"\n")
	writeEnvFile(t, project, "schemaVersion: \"1\"\nworkspace: \"${{ env.fileDir }}/src\"\n")

	plan, err := Load([]string{project, base})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(projectDir, "base"); plan.Workspace != want {
		t.Fatalf("workspace = %q, want %q", plan.Workspace, want)
	}
	if len(plan.AdditionalWorkspaces) != 1 {
		t.Fatalf("additional workspaces = %#v", plan.AdditionalWorkspaces)
	}
	if want := filepath.Join(baseDir, "shared"); plan.AdditionalWorkspaces[0].Path != want {
		t.Fatalf("additional workspace = %q, want %q", plan.AdditionalWorkspaces[0].Path, want)
	}
}

func TestLoadDefaultExpandsProjectDirectoryInHomeDefaults(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(homeDir, ".sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}\"\n")
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\n")

	plan, err := LoadDefault(homeDir, workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workspace != workingDir {
		t.Fatalf("workspace = %q, want project directory %q", plan.Workspace, workingDir)
	}
}

func TestLoadRejectsUnknownDirectoryReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.unknown }}\"\n")
	if _, err := Load([]string{path}); err == nil {
		t.Fatal("unknown environment reference accepted")
	}
}

func TestLoadAllowsExpandedDirectoryWithReferenceSyntaxInName(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project-${{literal}}")
	if err := os.Mkdir(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(projectDir, "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}/src\"\n")

	plan, err := Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(projectDir, "src"); plan.Workspace != want {
		t.Fatalf("workspace = %q, want %q", plan.Workspace, want)
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
		"missing sandbox port":    "schemaVersion: \"1\"\nagent: shell\nports:\n  - host: 3000\n",
		"invalid port protocol":   "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 3000\n    protocol: sctp\n",
		"invalid host ip":         "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 3000\n    hostIP: example.com\n",
		"out of range port":       "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 65536\n",
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
