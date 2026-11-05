package command

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{"completion", shell}); code != 0 {
			t.Fatalf("%s exit=%d output=%q", shell, code, out.String())
		}
		expectedCompletions := []string{"rsbx", "create", "remove", "unset"}
		if shell == "fish" {
			expectedCompletions = append(expectedCompletions, "-l token", "-s t", "-l all", "-s f", "-l force")
		} else {
			expectedCompletions = append(expectedCompletions, "--token", "-t", "--all", "-f", "--force")
		}
		for _, expected := range expectedCompletions {
			if !strings.Contains(out.String(), expected) {
				t.Errorf("%s output lacks %q: %s", shell, expected, out.String())
			}
		}
		if t.Failed() {
			t.Fatalf("%s output=%q", shell, out.String())
		}
	}
}

func TestSecretFlagsAndAliasesAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"--oauth", "--token", "-t", "--force", "-f", "--all", "--all-sandboxes", "--dry-run", "--sandbox", "--registry", "--global", "--quiet", "--service"} {
		if !slices.Contains(completionTree[secretCommand], expected) {
			t.Errorf("secret %s flag is missing from completion tree", expected)
		}
	}
	for _, expected := range []string{"import", "ls", "list", "set", "set-custom", "rm", "remove", "delete", "unset"} {
		if !slices.Contains(completionSubcommands[secretCommand], expected) {
			t.Errorf("secret %s command is missing from completion tree", expected)
		}
	}
}

func TestLogoutForceFlagsAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"-f", "--force"} {
		if !slices.Contains(completionTree["logout"], expected) {
			t.Errorf("logout %s flag is missing from completion tree", expected)
		}
	}
}

func TestFishCompletionUsesShortFlagSyntax(t *testing.T) {
	script := fishCompletionScript()
	for _, expected := range []string{"-l token", "-s t", "-s f", "-s g", "-s q"} {
		if !strings.Contains(script, expected) {
			t.Errorf("fish completion lacks %q", expected)
		}
	}
	if strings.Contains(script, "-l t\n") || strings.Contains(script, "-l f\n") {
		t.Fatalf("short flag is emitted as a long flag: %s", script)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"completion", "tcsh"}); code != 2 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
}
