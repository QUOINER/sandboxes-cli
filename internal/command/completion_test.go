package command

import (
	"bytes"
	"context"
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
		if !strings.Contains(out.String(), "rsbx") || !strings.Contains(out.String(), "create") {
			t.Fatalf("%s output=%q", shell, out.String())
		}
	}
}

func TestSecretOAuthFlagIsInCompletionTree(t *testing.T) {
	for _, flag := range completionTree[secretCommand] {
		if flag == "--oauth" {
			return
		}
	}
	t.Fatal("secret --oauth flag is missing from completion tree")
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"completion", "tcsh"}); code != 2 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
}
