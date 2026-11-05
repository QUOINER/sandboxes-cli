package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestSecretImportFailsClosedWhenInventoryCannotBeRead(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-token")
	secrets := &fakeServiceSecrets{listErr: errors.New("synthetic inventory failure")}
	client := fakeClient{secrets: secrets}
	var output bytes.Buffer
	runner := &Runner{
		Out: &output, Err: &output, In: strings.NewReader("y\n"),
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", "github"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "list stored secrets before import") {
		t.Fatalf("missing fail-closed error: %q", output.String())
	}
	if secrets.createCalls != 0 || secrets.service != "" {
		t.Fatalf("secret write attempted after failed inventory: create calls=%d service=%q", secrets.createCalls, secrets.service)
	}
}

func TestSecretImportUsesAtomicCreateUnlessForceIsExplicit(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-token")
	secrets := &fakeServiceSecrets{}
	client := fakeClient{secrets: secrets}
	var output bytes.Buffer
	runner := &Runner{
		Out: &output, Err: &output, In: strings.NewReader("y\n"),
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", "github"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if secrets.createCalls != 1 || secrets.service != "github" || secrets.scope != sdk.SecretScopeGlobal {
		t.Fatalf("import did not use create-only path: create calls=%d secret=%+v", secrets.createCalls, secrets)
	}
	if string(secrets.value) != "synthetic-token" {
		t.Fatalf("stored unexpected value %q", secrets.value)
	}

	output.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "import", "github", "--force"}); code != 0 {
		t.Fatalf("force exit=%d output=%q", code, output.String())
	}
	if secrets.createCalls != 1 || secrets.service != "github" {
		t.Fatalf("--force did not use explicit overwrite path: create calls=%d secret=%+v", secrets.createCalls, secrets)
	}
}
