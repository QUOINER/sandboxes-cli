package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestSecretImportHelpDocumentsBehaviorAndOAuthScope(t *testing.T) {
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output}
	if code := runner.secretImportHelp(); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	for _, want := range []string{
		"--all adds new values without prompts and leaves existing ones intact.",
		"--force saves every detected value, replacing existing entries too.",
		"A stored OpenAI OAuth session takes precedence over OPENAI_API_KEY.",
		"--dry-run never writes",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("help missing %q: %q", want, output.String())
		}
	}
}

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

func TestSecretImportUnknownFlagMatchesDockerDiagnostic(t *testing.T) {
	var output bytes.Buffer
	clientCalled := false
	runner := &Runner{
		Out: &output, Err: &output, In: strings.NewReader(""),
		NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return fakeClient{}, nil
		},
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", "--bad-option"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	want := "error: unknown flag: --bad-option\n  try: rsbx secret import --help\n"
	if output.String() != want {
		t.Fatalf("output=%q, want %q", output.String(), want)
	}
	if clientCalled {
		t.Fatal("unknown flag contacted daemon")
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
		if !strings.Contains(output.String(), "0 secrets imported · 1 skipped") {
			t.Fatalf("missing imported/skipped summary: %q", output.String())
		}
		if strings.Contains(output.String(), "no environment variable found") {
			t.Fatalf("declined import was reported as a missing environment variable: %q", output.String())
		}
	})
}

func TestSecretImportEmptyLineAcceptsDefaultYesButEOFCancels(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-token")
	for _, test := range []struct {
		name       string
		input      string
		wantCreate int
	}{
		{name: "empty line accepts default yes", input: "\n", wantCreate: 1},
		{name: "eof cancels", input: "", wantCreate: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			secrets := &fakeServiceSecrets{}
			client := fakeClient{secrets: secrets}
			var output bytes.Buffer
			runner := &Runner{
				Out: &output, Err: &output, In: strings.NewReader(test.input),
				NewClient: func(string) (sdk.Client, error) { return client, nil },
			}
			if code := runner.Run(context.Background(), []string{"secret", "import", "github"}); code != 0 {
				t.Fatalf("exit=%d output=%q", code, output.String())
			}
			if secrets.createCalls != test.wantCreate {
				t.Fatalf("create calls=%d, want %d; output=%q", secrets.createCalls, test.wantCreate, output.String())
			}
			if !strings.Contains(output.String(), "(Y/n)") {
				t.Fatalf("missing Docker default-yes prompt: %q", output.String())
			}
		})
	}
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

func TestSecretImportReportsMissingEnvironmentVariableLikeDocker(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	for _, args := range [][]string{
		{"secret", "import", "github"},
		{"secret", "import", "github", "--dry-run"},
	} {
		client := fakeClient{secrets: &fakeServiceSecrets{}}
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return client, nil }}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, output.String())
		}
		want := `No env var detected for "github" on the host. Either the env var isn't set, or "github" isn't a known credential service.`
		if !strings.Contains(output.String(), want) {
			t.Errorf("%v missing Docker-compatible empty-environment message: %q", args, output.String())
		}
	}
}

func TestSecretImportReportsNoDetectedCredentialsLikeDocker(t *testing.T) {
	for _, names := range serviceEnvVars {
		for _, name := range names {
			t.Setenv(name, "")
		}
	}
	for _, args := range [][]string{
		{"secret", "import"},
		{"secret", "import", "--dry-run"},
	} {
		client := fakeClient{secrets: &fakeServiceSecrets{}}
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return client, nil }}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, output.String())
		}
		want := "No credential env vars detected on the host. Set e.g. OPENAI_API_KEY in your shell and re-run, or use `rsbx secret set` to enter a value directly."
		if !strings.Contains(output.String(), want) {
			t.Errorf("%v missing Docker-compatible diagnostic: %q", args, output.String())
		}
	}
}

func TestSecretImportUnknownServiceMatchesDockerDiagnostic(t *testing.T) {
	var output bytes.Buffer
	newClientCalled := false
	runner := &Runner{
		Out: &output, Err: &output,
		NewClient: func(string) (sdk.Client, error) {
			newClientCalled = true
			return fakeClient{secrets: &fakeServiceSecrets{}}, nil
		},
	}

	if code := runner.Run(context.Background(), []string{"secret", "import", "invalid-service", "--dry-run"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	want := "error: unknown service \"invalid-service\" (available: " + strings.Join(serviceSecretNames, ", ") + ")\n  try: rsbx secret import --help"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("missing Docker-compatible error: %q", output.String())
	}
	if newClientCalled {
		t.Fatal("unknown service reached the daemon")
	}
}

func TestSecretImportRejectsExtraPositionalsLikeDocker(t *testing.T) {
	var output bytes.Buffer
	newClientCalled := false
	runner := &Runner{
		Out: &output, Err: &output,
		NewClient: func(string) (sdk.Client, error) {
			newClientCalled = true
			return fakeClient{secrets: &fakeServiceSecrets{}}, nil
		},
	}
	if code := runner.Run(context.Background(), []string{"secret", "import", "github", "extra"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "error: accepts at most 1 arg(s), received 2\n  try: rsbx secret import --help") {
		t.Fatalf("missing Docker-compatible argument error: %q", output.String())
	}
	if newClientCalled {
		t.Fatal("invalid argument count reached the daemon")
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
