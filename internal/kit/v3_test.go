package kit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const v3Mixin = `# syntax=docker/sandbox-kit:3
schemaVersion: "3"
displayName: GitHub CLI
description: gh, installed from the official release tarball
sourceUrl: https://github.com/cli/cli
licenses: [MIT]
kind: mixin
args:
  version:
    default: "2.98.0"
    pattern: '^[0-9]+\.[0-9]+\.[0-9]+$'
    description: GitHub CLI release to install
    buildArg: GH_VERSION
provides: ["gh@${{ kit.args.version }}"]
capabilities:
  - type: com.docker.sandbox/network-policy@1
    config:
      runtime:
        allow: [github.com, api.github.com]
  - type: com.docker.sandbox/credential@1
    optional: true
    name: GitHub access
    config:
      service: github
      phase: runtime
`

func TestDecodeV3Mixin(t *testing.T) {
	doc, err := Decode(strings.NewReader(v3Mixin))
	if err != nil {
		t.Fatal(err)
	}
	v3 := doc.V3
	if v3 == nil {
		t.Fatal("descriptor was not recognized as kit v3")
	}
	if v3.Kind != "mixin" || v3.DisplayName != "GitHub CLI" || v3.SchemaVersion != "3" {
		t.Fatalf("descriptor=%+v", v3)
	}
	if len(v3.Capabilities) != 2 || v3.Capabilities[0].Type != "com.docker.sandbox/network-policy@1" {
		t.Fatalf("capabilities=%+v", v3.Capabilities)
	}
	if v3.Args["version"].BuildArg != "GH_VERSION" || !v3.Args["version"].HasDefault {
		t.Fatalf("args=%+v", v3.Args)
	}
	if v3.NeedsBuild {
		t.Fatal("decoded descriptor must not claim build state")
	}
}

func TestDecodeV3RejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"unknown top-level field": "schemaVersion: \"3\"\nkind: mixin\nunexpected: true\n",
		"bad kind":                "schemaVersion: \"3\"\nkind: wizard\n",
		"schemaVersion not 3":     "schemaVersion: \"4\"\nkind: mixin\n",
		"NUL byte":                "schemaVersion: \"3\"\nkind: mixin\x00\n",
		"http iconUrl":            "schemaVersion: \"3\"\nkind: mixin\niconUrl: http://example.com/i.png\n",
		"bad version":             "schemaVersion: \"3\"\nkind: mixin\nversion: v1.2\n",
		"dockerfile escapes":      "schemaVersion: \"3\"\nkind: mixin\ndockerfile: ../Dockerfile\n",
		"recipe conflict":         "schemaVersion: \"3\"\nkind: mixin\nbuild: |\n  FROM scratch\nkits:\n  - ref: registry.example/x:1.0.0\n",
		"set without kits":        "schemaVersion: \"3\"\nkind: set\ndisplayName: empty\n",
		"set with local ref":      "schemaVersion: \"3\"\nkind: set\nkits:\n  - ref: ./hello\n",
		"set with bad digest":     "schemaVersion: \"3\"\nkind: set\nkits:\n  - ref: registry.example/kit:1.0.0\n    digest: md5:xyz\n",
		"set with non-hex digest": "schemaVersion: \"3\"\nkind: set\nkits:\n  - ref: registry.example/kit:1.0.0\n    digest: sha256:" + strings.Repeat("g", 64) + "\n",
		"bad capability type":     "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: network-policy\n",
		"capability version text": "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: com.docker.sandbox/network-policy@x\n",
		"duplicate capability": "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n" +
			"  - {type: com.docker.sandbox/credential@1, config: {service: github, phase: runtime}}\n" +
			"  - {type: com.docker.sandbox/credential@1, config: {service: github, phase: runtime}}\n",
		"singleton duplicated": "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n" +
			"  - {type: com.docker.sandbox/resources@1}\n  - {type: com.docker.sandbox/resources@1}\n",
		"network-policy both": "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n" +
			"  - {type: com.docker.sandbox/network-policy@1}\n  - {type: com.docker.sandbox/network-policy@2}\n",
		"group with type":          "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group: {capabilities: [{type: com.docker.sandbox/privileged@1}]}\n    type: com.docker.sandbox/privileged@1\n",
		"empty group":              "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group: {name: empty}\n",
		"nested group":             "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group: {capabilities: [{group: {capabilities: [{type: com.docker.sandbox/privileged@1}]}}]}\n",
		"member declarationBlocks": "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - group: {capabilities: [{type: com.docker.sandbox/privileged@1, declarationBlocks: [a]}]}\n",
		"undeclared arg reference": "schemaVersion: \"3\"\nkind: mixin\nprovides: [\"gh@${{ kit.args.version }}\"]\n",
		"build secret referenced":  "schemaVersion: \"3\"\nkind: mixin\nargs:\n  token: {buildSecret: id}\nprovides: [\"gh@${{ kit.args.token }}\"]\n",
		"reference in requires":    "schemaVersion: \"3\"\nkind: mixin\nrequires: [\"gh >= ${{ kit.args.version }}\"]\n",
		"default and required":     "schemaVersion: \"3\"\nkind: mixin\nargs:\n  name: {default: \"\", required: true}\n",
		"enum and pattern":         "schemaVersion: \"3\"\nkind: mixin\nargs:\n  name: {enum: [a], pattern: '^a$'}\n",
		"two deliveries":           "schemaVersion: \"3\"\nkind: mixin\nargs:\n  name: {env: A, buildArg: B}\n",
		"bad arg key":              "schemaVersion: \"3\"\nkind: mixin\nargs:\n  9lives: {}\n",
		"bad arg pattern":          "schemaVersion: \"3\"\nkind: mixin\nargs:\n  name: {pattern: '[unclosed'}\n",
		"bad provides version":     "schemaVersion: \"3\"\nkind: mixin\nprovides: [gh@v1]\n",
		"bad provides name":        "schemaVersion: \"3\"\nkind: mixin\nprovides: [Gh]\n",
		"reserved derived name":    "schemaVersion: \"3\"\nkind: mixin\nprovides: [deb/bash]\n",
		"requires bad constraint":  "schemaVersion: \"3\"\nkind: mixin\nrequires: [\"docker-engine ~= 25\"]\n",
		"requires trailing op":     "schemaVersion: \"3\"\nkind: mixin\nrequires: [\"node >= 20.0.0,\"]\n",
		"conflicts constrained":    "schemaVersion: \"3\"\nkind: mixin\nconflicts: [\"podman >= 1\"]\n",
		"bad namespace":            "schemaVersion: \"3\"\nkind: mixin\nrequires: [com..example/gh]\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(body)); err == nil {
				t.Fatalf("accepted invalid kit v3 descriptor:\n%s", body)
			}
		})
	}
}

func TestDecodeV3AcceptsSandboxSpellingAndConstraints(t *testing.T) {
	body := `schemaVersion: "3"
kind: sandbox
provides: [com.example/gh@2.98.0]
requires: ["node >= 20.0.0, < 21.0.0", git]
integrates: ["docker-engine >= 25.0.0"]
conflicts: [podman]
`
	doc, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if doc.V3.Kind != "workload" {
		t.Fatalf("sandbox kind must normalize to workload, got %q", doc.V3.Kind)
	}
}

func TestDecodeV3Set(t *testing.T) {
	body := `schemaVersion: "3"
kind: set
displayName: Team environment
version: "1.0.0"
kits:
  - ref: registry.example.com/team/sbx-kit-shell:1.0.0
    args: {version: "1.0.0"}
  - ref: registry.example.com/team/sbx-kit-gh:2.72.0
    digest: sha256:` + strings.Repeat("a", 64) + `
`
	doc, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if doc.V3.Kind != "set" || len(doc.V3.Kits) != 2 {
		t.Fatalf("descriptor=%+v", doc.V3)
	}
}

func TestLoadV3KitDirectory(t *testing.T) {
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "probe")
	if err := os.Mkdir(kitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(v3Mixin, "kind: mixin", "kind: mixin\nbuild: |\n  FROM scratch\n", 1)
	if err := os.WriteFile(filepath.Join(kitDir, "probe.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(kitDir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.V3 == nil || doc.V3.DisplayName != "GitHub CLI" {
		t.Fatalf("descriptor=%+v", doc.V3)
	}
	if !doc.V3.NeedsBuild {
		t.Fatal("inline build recipe must mark the descriptor as needing a builder")
	}
}

func TestLoadV3DirectoryDetectsCompanionDockerfile(t *testing.T) {
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "tool")
	if err := os.Mkdir(kitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kitDir, "tool.yaml"), []byte(v3Mixin), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(kitDir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.V3.NeedsBuild {
		t.Fatal("declaration-only mixin without a companion recipe must not need a builder")
	}
	if err := os.WriteFile(filepath.Join(kitDir, "tool.dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err = Load(kitDir)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.V3.NeedsBuild {
		t.Fatal("companion dockerfile must mark the descriptor as needing a builder")
	}
}

func TestLoadPrefersSpecYAMLForV2Directory(t *testing.T) {
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "codex")
	if err := os.Mkdir(kitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	v2 := "schemaVersion: \"2\"\nkind: sandbox\nname: codex-kit\nsandbox: {image: example/codex:1.0.0}\n"
	if err := os.WriteFile(filepath.Join(kitDir, "spec.yaml"), []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(kitDir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.V3 != nil || doc.Metadata.Name != "codex-kit" || doc.Spec.Image != "example/codex:1.0.0" {
		t.Fatalf("kit=%+v", doc)
	}
}
