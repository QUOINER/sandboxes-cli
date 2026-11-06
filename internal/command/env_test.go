package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironmentPlanIsReadOnlyAndRedactsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	body := "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 3000\n    host: 4300\n    protocol: tcp4\nenv:\n  API_TOKEN: very-secret-value\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	code := runner.Run(context.Background(), []string{"env", "plan", path})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "API_TOKEN=<redacted>") || strings.Contains(stdout.String(), "very-secret-value") || !strings.Contains(stdout.String(), "sandbox 3000 -> host 4300 (tcp4, hostIP default)") {
		t.Fatalf("unexpected preview output: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "daemon state not queried") {
		t.Fatalf("preview limitation missing: %s", stdout.String())
	}
}

func TestEnvironmentPlanArgumentOverridesAreRedacted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sbxenv.yaml")
	argumentFile := filepath.Join(root, "args.txt")
	body := "schemaVersion: \"1\"\nagent: shell\nargs:\n  mode:\n    default: stable-secret-default\n    enum: [stable-secret-default, beta-secret]\n  api_key:\n    required: true\n    pattern: '[a-z-]+'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(argumentFile, []byte("mode=invalid-file-value\napi_key=file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	args := []string{"env", "plan", path, "--env-args-file", argumentFile, "--env-arg", "mode=beta-secret", "--env-arg", "api_key=cli-secret"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	output := stdout.String()
	for _, secret := range []string{"stable-secret-default", "invalid-file-value", "file-secret", "beta-secret", "cli-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("environment argument value leaked: %q", output)
		}
	}
	if !strings.Contains(output, "mode=<redacted>") || !strings.Contains(output, "api_key=<redacted>") {
		t.Fatalf("argument names were not shown with redacted values: %q", output)
	}
}

func TestEnvironmentPlanRedactsArgumentsInterpolatedIntoPreviewFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	body := "schemaVersion: \"1\"\nname: ${{ env.args.name }}\nagent: ${{ env.args.agent }}\nworkspace: ${{ env.args.workspace }}\nadditionalWorkspaces:\n  - path: ${{ env.args.extra }}\nports:\n  - sandbox: ${{ env.args.port }}\nsandboxOptions:\n  cpus: ${{ env.args.cpus }}\n  memory: ${{ env.args.memory }}\nargs:\n"
	for _, name := range []string{"name", "agent", "workspace", "extra", "port", "cpus", "memory"} {
		body += "  " + name + ":\n    required: true\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	values := []string{
		"name=private-name",
		"agent=private-agent",
		"workspace=private-workspace",
		"extra=private-extra-workspace",
		"port=32123",
		"cpus=4",
		"memory=2g",
	}
	args := make([]string, 0, 3+2*len(values))
	args = append(args, "env", "plan", path)
	for _, value := range values {
		args = append(args, "--env-arg", value)
	}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	output := stdout.String()
	for _, value := range []string{"private-name", "private-agent", "private-workspace", "private-extra-workspace", "32123", "CPUs: 4", "2g"} {
		if strings.Contains(output, value) {
			t.Fatalf("interpolated argument value %q leaked: %q", value, output)
		}
	}
	for _, field := range []string{"Name: <redacted>", "Agent: <redacted>", "Workspace: <redacted>", "  <redacted> (read-write)", "CPUs: <redacted>", "Memory: <redacted>"} {
		if !strings.Contains(output, field) {
			t.Fatalf("redacted field %q missing: %q", field, output)
		}
	}
}

func TestEnvironmentPlanEscapesWorkspaceControlCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	body := "schemaVersion: \"1\"\nagent: shell\nworkspace: \"line\\nINJECT\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	if code := runner.Run(context.Background(), []string{"env", "plan", path}); code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "line\nINJECT") || !strings.Contains(stdout.String(), `line\nINJECT`) {
		t.Fatalf("workspace path was not safely quoted: %q", stdout.String())
	}
}

func TestEnvironmentMutatingCommandsFailClosed(t *testing.T) {
	for _, args := range [][]string{{"env", "create"}, {"env", "run", "./"}, {"env", "rm", "x"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runner := NewRunner(&stdout, &stderr)
			if code := runner.Run(context.Background(), args); code == 0 {
				t.Fatal("unsupported command unexpectedly succeeded")
			}
			if !strings.Contains(stderr.String(), "unsupported") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestEnvironmentPlanDefaultsAndExplicitPathPrecedence(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	homeFile := filepath.Join(homeDir, ".sbxenv.yaml")
	projectFile := filepath.Join(workingDir, "sbxenv.yaml")
	if err := os.WriteFile(homeFile, []byte("schemaVersion: \"1\"\nagent: shell\nenv:\n  HOME_DEFAULT: private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectFile, []byte("schemaVersion: \"1\"\nagent: shell\nenv:\n  PROJECT_VALUE: visible\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	run := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		runner := NewRunner(&stdout, &stderr)
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("args %v: exit code %d, stderr: %s", args, code, stderr.String())
		}
		return stdout.String()
	}
	defaultOutput := run("env", "plan")
	if !strings.Contains(defaultOutput, "HOME_DEFAULT=<redacted>") || !strings.Contains(defaultOutput, "PROJECT_VALUE=<redacted>") {
		t.Fatalf("default precedence output = %q", defaultOutput)
	}
	if strings.Contains(defaultOutput, "private") || strings.Contains(defaultOutput, "visible") {
		t.Fatalf("environment values leaked: %q", defaultOutput)
	}
	explicitOutput := run("env", "plan", projectFile)
	if strings.Contains(explicitOutput, "HOME_DEFAULT") || !strings.Contains(explicitOutput, "PROJECT_VALUE=<redacted>") {
		t.Fatalf("explicit path did not skip home defaults: %q", explicitOutput)
	}
	nameOutput := run("env", "plan", projectFile, "--name", "override-name")
	if !strings.Contains(nameOutput, "Name: override-name\n") {
		t.Fatalf("--name did not override file/default name: %q", nameOutput)
	}
	var invalidOut, invalidErr bytes.Buffer
	invalidRunner := NewRunner(&invalidOut, &invalidErr)
	if code := invalidRunner.Run(context.Background(), []string{"env", "plan", "--name", "bad/name", projectFile}); code == 0 {
		t.Fatal("invalid --name was accepted")
	}
}
