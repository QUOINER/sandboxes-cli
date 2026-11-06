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
	body := "schemaVersion: \"1\"\nagent: shell\nenv:\n  API_TOKEN: very-secret-value\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	code := runner.Run(context.Background(), []string{"env", "plan", path})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "API_TOKEN=<redacted>") || strings.Contains(stdout.String(), "very-secret-value") {
		t.Fatalf("unexpected preview output: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "daemon state not queried") {
		t.Fatalf("preview limitation missing: %s", stdout.String())
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
}
