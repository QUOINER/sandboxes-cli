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
	runner.In = strings.NewReader("")
	if code := runner.Run(context.Background(), []string{"secret", "import", "github", "-f"}); code != 0 {
		t.Fatalf("force exit=%d output=%q", code, output.String())
	}
	if secrets.createCalls != 1 || secrets.setCalls != 1 || secrets.service != "github" {
		t.Fatalf("-f did not use explicit overwrite path: create calls=%d set calls=%d secret=%+v", secrets.createCalls, secrets.setCalls, secrets)
	}
	if strings.Contains(output.String(), "Import github from GH_TOKEN") {
		t.Fatalf("--force unexpectedly prompted: %q", output.String())
	}
}

func TestSecretImportSkipsOpenAIAPIKeyWhenOAuthIsStored(t *testing.T) {
	t.Setenv(openAIAPIKeyEnv, "synthetic-openai-key")
	secrets := &fakeServiceSecrets{}
	client := fakeClient{
		secrets:         secrets,
		accountStatuses: fakeAccountStatus{statuses: map[string]bool{openAIService: true}},
	}
	var output bytes.Buffer
	runner := &Runner{
		Out: &output, Err: &output, In: strings.NewReader("y\n"),
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", openAIService}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "OAuth credentials are already stored and take precedence") {
		t.Fatalf("OAuth precedence was not reported: %q", output.String())
	}
	if secrets.createCalls != 0 || secrets.service != "" {
		t.Fatalf("API key was imported despite OAuth presence: create calls=%d service=%q", secrets.createCalls, secrets.service)
	}
}

func TestSecretImportStopsBeforeWritesWhenOpenAIStatusIsUnavailable(t *testing.T) {
	t.Setenv(openAIAPIKeyEnv, "synthetic-openai-key")
	secrets := &fakeServiceSecrets{}
	client := fakeClient{
		secrets:         secrets,
		accountStatuses: fakeAccountStatus{err: errors.New("synthetic status failure")},
	}
	var output bytes.Buffer
	runner := &Runner{
		Out: &output, Err: &output, In: strings.NewReader("y\n"),
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", openAIService}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "check openai OAuth credentials before import") {
		t.Fatalf("missing status error: %q", output.String())
	}
	if secrets.createCalls != 0 || secrets.service != "" {
		t.Fatalf("write attempted after status failure: create calls=%d service=%q", secrets.createCalls, secrets.service)
	}
}

func TestSecretImportOverwriteModesMatchDockerPromptRules(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-token")
	existing := []sdk.ServiceSecret{{Service: "github", Scope: sdk.SecretScopeGlobal}}

	t.Run("interactive confirmation overwrites", func(t *testing.T) {
		secrets := &fakeServiceSecrets{items: existing}
		client := fakeClient{secrets: secrets}
		var output bytes.Buffer
		runner := &Runner{
			Out: &output, Err: &output, In: strings.NewReader("y\n"),
			NewClient: func(string) (sdk.Client, error) { return client, nil },
		}
		if code := runner.Run(context.Background(), []string{"secret", "import", "github"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, output.String())
		}
		if secrets.setCalls != 1 || secrets.createCalls != 0 || !strings.Contains(output.String(), "Overwrite github from GH_TOKEN") {
			t.Fatalf("interactive overwrite mismatch: set=%d create=%d output=%q", secrets.setCalls, secrets.createCalls, output.String())
		}
	})

	t.Run("all skips existing entries", func(t *testing.T) {
		secrets := &fakeServiceSecrets{items: existing}
		client := fakeClient{secrets: secrets}
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return client, nil }}
		if code := runner.Run(context.Background(), []string{"secret", "import", "github", "--all"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, output.String())
		}
		if secrets.setCalls != 0 || secrets.createCalls != 0 || !strings.Contains(output.String(), "already stored") {
			t.Fatalf("--all did not skip existing entry: set=%d create=%d output=%q", secrets.setCalls, secrets.createCalls, output.String())
		}
	})

	t.Run("negative confirmation leaves existing entry untouched", func(t *testing.T) {
		secrets := &fakeServiceSecrets{items: existing}
		client := fakeClient{secrets: secrets}
		var output bytes.Buffer
		runner := &Runner{
			Out: &output, Err: &output, In: strings.NewReader("n\n"),
			NewClient: func(string) (sdk.Client, error) { return client, nil },
		}
		if code := runner.Run(context.Background(), []string{"secret", "import", "github"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, output.String())
		}
		if secrets.setCalls != 0 || secrets.createCalls != 0 || !strings.Contains(output.String(), "Overwrite github from GH_TOKEN") {
			t.Fatalf("negative control modified or did not prompt for existing entry: set=%d create=%d output=%q", secrets.setCalls, secrets.createCalls, output.String())
		}
		if strings.Contains(output.String(), "no environment variable found") {
			t.Fatalf("declined import was reported as a missing environment variable: %q", output.String())
		}
	})
}

func TestSecretImportDryRunShowsOnlyLastFourPreviewAndDoesNotWrite(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-parity-token")
	secrets := &fakeServiceSecrets{}
	client := fakeClient{secrets: secrets}
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return client, nil }}

	if code := runner.Run(context.Background(), []string{"secret", "import", "github", "--dry-run"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "Would import github from GH_TOKEN (last 4: oken)") {
		t.Fatalf("missing Docker-style masked preview: %q", output.String())
	}
	if strings.Contains(output.String(), "synthetic-parity-token") || secrets.createCalls != 0 || secrets.setCalls != 0 {
		t.Fatalf("dry-run leaked the full value or wrote a secret: output=%q create=%d set=%d", output.String(), secrets.createCalls, secrets.setCalls)
	}
}

func TestLastFourPreviewMasksShortValues(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "", want: ""},
		{value: "x", want: "•"},
		{value: "abc", want: "•••"},
		{value: "abcd", want: "••••"},
		{value: "abcde", want: "bcde"},
		{value: "ключ-секрет", want: "крет"},
	}
	for _, test := range tests {
		if got := lastFourPreview(test.value); got != test.want {
			t.Errorf("lastFourPreview(%q)=%q, want %q", test.value, got, test.want)
		}
	}
}
