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
