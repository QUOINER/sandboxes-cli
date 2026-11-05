package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &out, &out); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if out.Len() == 0 {
		t.Fatal("empty output")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"unknown"}, &out, &out); code != 2 {
		t.Fatalf("exit code %d", code)
	}
}

func TestCreateUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"create", "dev"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "SANDBOX") || !strings.Contains(out.String(), "Created sandbox dev") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

type fakeExecClient struct{ fakeClient }

func (fakeExecClient) Executor() sdk.Executor { return fakeExecutor{} }

type fakeExecutor struct{}

func (fakeExecutor) Exec(_ context.Context, req sdk.ExecRequest) (int, error) {
	if req.SandboxID != "sb-1" || len(req.Argv) != 2 || req.Argv[0] != "printf" || req.Workdir != "/workspace" {
		return 0, io.ErrUnexpectedEOF
	}
	_, err := io.WriteString(req.Stdout, "fixture")
	return 0, err
}

func TestExecUsesSDKAndResolvesName(t *testing.T) {
	var out, stderr bytes.Buffer
	runner := &Runner{Out: &out, Err: &stderr, NewClient: func(string) (sdk.Client, error) { return fakeExecClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"exec", "-w", "/workspace", "dev", "printf", "fixture"}); code != 0 || out.String() != "fixture" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if code := runner.Run(context.Background(), []string{"exec", "missing", "true"}); code != 125 {
		t.Fatalf("missing sandbox code=%d", code)
	}
}

func TestListUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "dev") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestListFollowsPagesAndRejectsCycles(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
			return fakeClient{sandbox: pagedSandbox{cycle: cycle}}, nil
		}}
		code := runner.Run(context.Background(), []string{"ls", "--limit", "1"})
		if cycle {
			if code != 1 || !strings.Contains(out.String(), "invalid sandbox pagination") {
				t.Fatalf("cycle: exit %d, output %q", code, out.String())
			}
			continue
		}
		if code != 0 || !strings.Contains(out.String(), "first") || !strings.Contains(out.String(), "second") {
			t.Fatalf("missing page: exit %d, output %q", code, out.String())
		}
	}
}

func TestWaitFailedOperationReturnsFailure(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{operations: failedOperations{}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"wait", "op-1"}); code != 1 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
}

func TestWaitSuccessfulOperationReturnsSuccess(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"wait", "op-1"}); code != 0 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
}

func TestLoginUsesStdinAndDoesNotPrintPassword(t *testing.T) {
	var out bytes.Buffer
	registry := &fakeRegistryCredentials{}
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		In:        strings.NewReader("synthetic-token\n"),
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{registry: registry}, nil },
	}
	if code := runner.Run(context.Background(), []string{"secret", "set", "--registry", "ghcr.io", "--username", "alice", "--password-stdin", "--sandbox", "sample"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if registry.password != "synthetic-token" || registry.request.Scope != sdk.RegistryScopeSandbox || registry.request.SandboxName != "sample" {
		t.Fatalf("unexpected login request: %#v", registry.request)
	}
	if strings.Contains(out.String(), "synthetic-token") || !strings.Contains(out.String(), "ghcr.io") {
		t.Fatalf("login output leaked a secret or omitted registry: %q", out.String())
	}
}

func TestOpenAIOAuthSecretCommandsUseHostAccountService(t *testing.T) {
	for _, args := range [][]string{{"secret", "set", "openai", "--oauth"}, {"secret", "rm", "openai", "--oauth", "--force"}} {
		var out bytes.Buffer
		accounts := &fakeAccounts{}
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("must-not-be-read\n"), Socket: "unused", NewClient: func(string) (sdk.Client, error) {
			return fakeClient{accounts: accounts, accountStatuses: fakeAccountStatus{statuses: map[string]bool{openAIService: true}}}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), "openai OAuth credentials") || strings.Contains(out.String(), "must-not-be-read") {
			t.Fatalf("%v: unexpected output %q", args, out.String())
		}
	}
}

func TestOpenAIOAuthSecretCommandRejectsUnsupportedScopeBeforeConnecting(t *testing.T) {
	var out bytes.Buffer
	clientCalled := false
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		clientCalled = true
		return fakeClient{accounts: &fakeAccounts{}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"secret", "set", "anthropic", "--oauth"}); code != 2 || clientCalled {
		t.Fatalf("exit=%d client-called=%t output=%q", code, clientCalled, out.String())
	}
}

func TestRegistrySecretRemovalUsesSDK(t *testing.T) {
	tests := []struct {
		args        []string
		want        []sdk.RegistryCredentialScope
		wantSandbox string
	}{
		{args: []string{"secret", "rm", "--registry", "ghcr.io", "--force"}, want: []sdk.RegistryCredentialScope{sdk.RegistryScopeHostOnly, sdk.RegistryScopeAllSandboxes}},
		{args: []string{"secret", "rm", "--registry", "ghcr.io", "--all-sandboxes", "--force"}, want: []sdk.RegistryCredentialScope{sdk.RegistryScopeAllSandboxes}},
		{args: []string{"secret", "rm", "--registry", "ghcr.io", "--sandbox", "dev", "-f"}, want: []sdk.RegistryCredentialScope{sdk.RegistryScopeSandbox}, wantSandbox: "dev"},
	}
	for _, test := range tests {
		var out bytes.Buffer
		registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeAllSandboxes)},
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
		}}
		runner := &Runner{
			Out: &out, Err: &out, Socket: "unused",
			NewClient: func(string) (sdk.Client, error) { return fakeClient{registry: registry}, nil },
		}
		if code := runner.Run(context.Background(), test.args); code != 0 {
			t.Fatalf("%v: exit code %d, output %s", test.args, code, out.String())
		}
		if !strings.Contains(out.String(), "ghcr.io") || strings.Contains(out.String(), "synthetic-token") {
			t.Fatalf("%v: unexpected logout output %q", test.args, out.String())
		}
		if len(registry.requests) != len(test.want) {
			t.Fatalf("%v: requests=%#v want scopes=%#v", test.args, registry.requests, test.want)
		}
		for index, scope := range test.want {
			if registry.requests[index].Scope != scope || registry.requests[index].SandboxName != test.wantSandbox {
				t.Fatalf("%v: request scopes=%#v want=%#v", test.args, registry.requests, test.want)
			}
		}
	}
}

func TestRegistryRemovalChecksInventoryBeforeConfirmation(t *testing.T) {
	t.Run("missing credential reports missing target", func(t *testing.T) {
		var out bytes.Buffer
		registry := &fakeRegistryCredentials{}
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
			return fakeClient{registry: registry}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "--registry", "ghcr.io", "--global"}); code != 1 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		want := "warning: --global is deprecated; global is now the default for service secrets; omit --global, use --sandbox to target one sandbox, or use --all-sandboxes with --registry\nerror: no registry secret found for \"ghcr.io\" in scope \"(global)\"\n"
		if out.String() != want || len(registry.requests) != 0 {
			t.Fatalf("output=%q removals=%d, want %q and no mutation", out.String(), len(registry.requests), want)
		}
	})

	t.Run("inventory error blocks prompt and mutation", func(t *testing.T) {
		var out bytes.Buffer
		registry := &fakeRegistryCredentials{listErr: errors.New("synthetic inventory failure")}
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
			return fakeClient{registry: registry}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "--registry", "ghcr.io", "--force"}); code != 1 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "list registry credentials before removal: synthetic inventory failure") || len(registry.requests) != 0 {
			t.Fatalf("output=%q removals=%d", out.String(), len(registry.requests))
		}
	})
}

func TestSecretRemoveAllSandboxesRequiresRegistryBeforeConnecting(t *testing.T) {
	var out bytes.Buffer
	clientCalled := false
	runner := &Runner{
		Out: &out, Err: &out,
		NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return fakeClient{}, nil
		},
	}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--all-sandboxes", "--force"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	want := "error: --all-sandboxes requires --registry\n  try: rsbx secret rm --help\n"
	if out.String() != want {
		t.Fatalf("output=%q, want %q", out.String(), want)
	}
	if clientCalled {
		t.Fatal("invalid scope called daemon")
	}
}

func TestDockerLegacySecretRemovalScopesAndGlobalAlias(t *testing.T) {
	t.Run("service positional scope", func(t *testing.T) {
		var out bytes.Buffer
		secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "legacy-sandbox"}}}
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			return fakeClient{secrets: secrets}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "legacy-sandbox", "github", "-f"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if len(secrets.removed) != 1 || secrets.removed[0].Service != "github" || secrets.removed[0].Scope != sdk.SecretScopeSandbox || secrets.removed[0].SandboxName != "legacy-sandbox" {
			t.Fatalf("wrong legacy removal scope: %+v", secrets.removed)
		}
		if !strings.Contains(out.String(), "positional sandbox scope is deprecated") || !strings.Contains(out.String(), "secret rm github --sandbox legacy-sandbox") {
			t.Fatalf("missing migration warning: %q", out.String())
		}
	})

	t.Run("global alias on service", func(t *testing.T) {
		var out bytes.Buffer
		secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: "github", Scope: sdk.SecretScopeGlobal}}}
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			return fakeClient{secrets: secrets}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "github", "--global", "-f"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if len(secrets.removed) != 1 || secrets.removed[0].Scope != sdk.SecretScopeGlobal {
			t.Fatalf("--global did not select global scope: %+v", secrets.removed)
		}
		if !strings.Contains(out.String(), "--global is deprecated") {
			t.Fatalf("missing deprecation warning: %q", out.String())
		}
	})

	t.Run("registry positional scope", func(t *testing.T) {
		var out bytes.Buffer
		registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "legacy-sandbox"}}}
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			return fakeClient{registry: registry}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "--registry", "ghcr.io", "legacy-sandbox", "-f"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if len(registry.requests) != 1 || registry.requests[0].Scope != sdk.RegistryScopeSandbox || registry.requests[0].SandboxName != "legacy-sandbox" {
			t.Fatalf("wrong registry legacy scope: %+v", registry.requests)
		}
		if !strings.Contains(out.String(), "use --sandbox legacy-sandbox with --registry") {
			t.Fatalf("missing migration warning: %q", out.String())
		}
	})

	t.Run("global registry selects host-only", func(t *testing.T) {
		var out bytes.Buffer
		registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)}}}
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			return fakeClient{registry: registry}, nil
		}}
		if code := runner.Run(context.Background(), []string{"secret", "rm", "--registry", "ghcr.io", "--global", "-f"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if len(registry.requests) != 1 || registry.requests[0].Scope != sdk.RegistryScopeHostOnly {
			t.Fatalf("--global registry scope requests=%+v", registry.requests)
		}
	})
}

func TestSecretRemovalRejectsDockerScopeConflictsBeforeConnecting(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"secret", "rm", "--all", "--global"}, want: "error: if any flags in the group [all global] are set none of the others can be; [all global] were all set\n  try: rsbx secret rm --help\n"},
		{args: []string{"secret", "rm", "--global", "--sandbox", "sample", "github"}, want: "error: cannot specify both --global and --sandbox\n  try: rsbx secret rm --help\n"},
		{args: []string{"secret", "rm", "--registry", "ghcr.io", "--all-sandboxes", "--sandbox", "sample"}, want: "error: cannot combine --sandbox with --global or --all-sandboxes\n  try: rsbx secret rm --help\n"},
		{args: []string{"secret", "rm", "--registry", "ghcr.io", "legacy-scope", "--sandbox", "sample"}, want: "error: cannot combine a positional sandbox name with a scope flag\n  try: rsbx secret rm --help\n"},
		{args: []string{"secret", "rm", "legacy-scope", "github", "--sandbox", "sample"}, want: "error: accepts at most 1 SERVICE argument when --global or --sandbox is used\n  try: rsbx secret rm --help\n"},
	}
	for _, test := range tests {
		var out bytes.Buffer
		clientCalled := false
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return fakeClient{}, nil
		}}
		if code := runner.Run(context.Background(), test.args); code != 1 {
			t.Errorf("%v: exit=%d output=%q", test.args, code, out.String())
		}
		if out.String() != test.want {
			t.Errorf("%v: output=%q, want %q", test.args, out.String(), test.want)
		}
		if clientCalled {
			t.Errorf("%v: conflicting scopes connected to daemon", test.args)
		}
	}
}

func TestSecretRemoveAllRejectsServiceArgumentLikeDocker(t *testing.T) {
	var out bytes.Buffer
	clientCalled := false
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		clientCalled = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--all", "synthetic-invalid-service"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	want := "error: cannot specify a SERVICE argument when using --all\n  try: rsbx secret rm --help\n"
	if out.String() != want || clientCalled {
		t.Fatalf("output=%q client-called=%t, want %q without client call", out.String(), clientCalled, want)
	}
}

func TestSecretRemovalAliasesDispatchToServiceAndRegistryRemoval(t *testing.T) {
	for _, alias := range []string{"remove", "delete", "unset"} {
		for _, args := range [][]string{{"secret", alias, "openai"}, {"secret", alias, "--registry", "ghcr.io"}} {
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
				return nil, errors.New("synthetic connection failure")
			}}
			args = append(args, "--force")
			if code := runner.Run(context.Background(), args); code != 1 || !strings.Contains(out.String(), "synthetic connection failure") || strings.Contains(out.String(), "unknown secret command") {
				t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
			}
		}
	}
}

func TestSecretRemovalHelpListsAliasesAndImplementedFlags(t *testing.T) {
	for _, command := range []string{"rm", "remove", "delete", "unset"} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{"secret", command, "--help"}); code != 0 {
			t.Fatalf("%s: exit=%d output=%q", command, code, out.String())
		}
		for _, expected := range []string{"Aliases:", "rm, remove, delete, unset", "--oauth", "--registry", "--all-sandboxes", "--sandbox", "--force"} {
			if !strings.Contains(out.String(), expected) {
				t.Errorf("%s: help lacks %q: %s", command, expected, out.String())
			}
		}
	}
}

func TestSecretSetHelpDocumentsInteractiveServiceChoiceAndLimits(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"secret", "set", "--help"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, expected := range []string{"[SERVICE]", "arrow keys", "anthropic", "openai", "-t, --token string", "--force", "--ref string      Use a 1Password op:// reference or AWS Secrets Manager ARN", "--command string  Run a host shell command to resolve a secret (can access host files)", "--refresh string", "--no-verify", "--show-error", "Registry credentials", "--registry string", "--password-stdin", "Cross-host registry authentication endpoints are not supported yet."} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("help lacks %q: %s", expected, out.String())
		}
	}
}

func TestRootHelpListsSupportedAndUnsupportedDockerCommandFamilies(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, expected := range []string{"Sandbox commands:", "Management commands:", "agents, daemon", "Extensions:", "reset", "template", "Unsupported Docker Sandboxes commands:", "mcp, move", "volume", "--socket PATH"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("root help lacks %q: %s", expected, out.String())
		}
	}
}

func TestAgentManagementCommandListsBuiltins(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"agents", "ls", "--format", "json"}); code != 0 || !strings.Contains(out.String(), `"name": "claude"`) {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
}

func TestSecretRemovalRequiresForceOutsideInteractiveTerminal(t *testing.T) {
	for _, test := range []struct {
		args   []string
		client sdk.Client
	}{
		{
			args: []string{"secret", "rm", "openai"},
			client: fakeClient{
				secrets:         &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: openAIService, Scope: sdk.SecretScopeGlobal}}},
				accountStatuses: fakeAccountStatus{statuses: map[string]bool{openAIService: true}},
			},
		},
		{
			args: []string{"secret", "rm", "--registry", "ghcr.io"},
			client: fakeClient{registry: &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{
				{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
				{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeAllSandboxes)},
			}}},
		},
	} {
		var out bytes.Buffer
		clientCalled := false
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("yes\n"), NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return test.client, nil
		}}
		want := "error: stdin is not a terminal; use --force to skip confirmation\n"
		if len(test.args) > 2 && test.args[2] == openAIService {
			want = "SCOPE      SERVICE   SECRET\n(global)   openai    \n" + want
		}
		if code := runner.Run(context.Background(), test.args); code != 1 || !clientCalled || out.String() != want {
			t.Fatalf("%v: exit=%d client-called=%t output=%q", test.args, code, clientCalled, out.String())
		}
	}
}

func TestAccountCommandsUseAccountService(t *testing.T) {
	for _, command := range []string{"login", "logout"} {
		var out bytes.Buffer
		called := false
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\n"), NewClient: func(string) (sdk.Client, error) {
			called = true
			return fakeClient{accounts: &fakeAccounts{}}, nil
		}}
		args := []string{command}
		if command == "logout" {
			args = append(args, "--force")
		}
		if code := runner.Run(context.Background(), args); code != 0 || !called {
			t.Fatalf("%s: exit=%d client called=%t output=%q", command, code, called, out.String())
		}
		if command == "login" && (!strings.Contains(out.String(), "Docker verification code: ABCD-EFGH") || !strings.Contains(out.String(), "Press Enter to open https://login.example/device") || !strings.Contains(out.String(), "If the browser does not open, visit the URL above and enter the code.") || !strings.Contains(out.String(), "Waiting for Docker authorization")) {
			t.Fatalf("login omitted the device code or Enter handoff prompt: %q", out.String())
		}
		if strings.Contains(out.String(), "synthetic-token") {
			t.Fatalf("account command consumed or printed registry input: %q", out.String())
		}
		for _, helpFlag := range []string{"--help", "-h"} {
			out.Reset()
			if code := runner.Run(context.Background(), []string{command, helpFlag}); code != 0 {
				t.Fatalf("%s %s exit=%d", command, helpFlag, code)
			}
			if command == "login" {
				for _, expected := range []string{"Description:\n  Sign in to Docker", "Examples:", "--password-stdin", "--username string"} {
					if !strings.Contains(out.String(), expected) {
						t.Fatalf("login help omitted %q: %q", expected, out.String())
					}
				}
				if strings.Contains(out.String(), "\n  -username") {
					t.Fatalf("login help exposed Go's short single-dash spelling: %q", out.String())
				}
			} else if !strings.Contains(out.String(), "Stop running local sandboxes and sign out of Docker") || !strings.Contains(out.String(), "-f, --force") {
				t.Fatalf("logout help omitted Docker-compatible description or force alias: %q", out.String())
			}
		}
	}
}

func TestLoginEOFCancelsBeforeDeviceHandoff(t *testing.T) {
	var out bytes.Buffer
	completed := false
	interactive := interactiveAccountFunc(func(ctx context.Context, _ string, handoff func(context.Context, sdk.DeviceLoginInfo) error) error {
		if err := handoff(ctx, sdk.DeviceLoginInfo{UserCode: "ABCD-EFGH", VerificationURI: "https://login.example/device"}); err != nil {
			return err
		}
		completed = true
		return nil
	})
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
		return fakeClient{interactive: interactive}, nil
	}}
	if code := runner.Run(context.Background(), []string{"login"}); code == 0 || completed {
		t.Fatalf("EOF should cancel before opening the browser, exit=%d completed=%t output=%q", code, completed, out.String())
	}
}

func TestLoginDockerPATReadsOneLineFromStdin(t *testing.T) {
	var out bytes.Buffer
	pat := &fakeDockerPATAccounts{}
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\r\n"), Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{dockerPAT: pat}, nil
	}}
	if code := runner.Run(context.Background(), []string{"login", "--username", "alice", "--password-stdin"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if pat.username != "alice" || string(pat.password) != "synthetic-token" {
		t.Fatalf("unexpected PAT login: %#v", pat)
	}
	if strings.Contains(out.String(), "synthetic-token") || !strings.Contains(out.String(), "Logged in") {
		t.Fatalf("unexpected login output %q", out.String())
	}
}

func TestLoginDockerPATRejectsInvalidStdinWithoutConnecting(t *testing.T) {
	for _, input := range []string{"", "one\ntwo\n", strings.Repeat("x", 2049)} {
		var out bytes.Buffer
		clientCalled := false
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(input), NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return fakeClient{}, nil
		}}
		if code := runner.Run(context.Background(), []string{"login", "--username", "alice", "--password-stdin"}); code != 2 || clientCalled {
			t.Fatalf("input length=%d: exit=%d client-called=%t output=%q", len(input), code, clientCalled, out.String())
		}
	}
}

func TestLogoutForceStopsRunningLocalSandboxes(t *testing.T) {
	for _, forceArg := range []string{"--force", "-f"} {
		t.Run(forceArg, func(t *testing.T) {
			var out bytes.Buffer
			sandbox := &logoutSandbox{}
			accounts := &fakeAccounts{}
			runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
				return fakeClient{sandbox: sandbox, accounts: accounts}, nil
			}}
			if code := runner.Run(context.Background(), []string{"logout", forceArg}); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if sandbox.stops != 1 || !strings.Contains(out.String(), "Stopped 1 running local sandbox") {
				t.Fatalf("logout did not stop the owned running sandbox: stops=%d output=%q", sandbox.stops, out.String())
			}
		})
	}
}

func TestLogoutRequiresConfirmationOrForceInNonTTY(t *testing.T) {
	var out bytes.Buffer
	clientCalled := false
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("y\n"), NewClient: func(string) (sdk.Client, error) {
		clientCalled = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"logout"}); code != 1 || clientCalled || !strings.Contains(out.String(), "use --force") {
		t.Fatalf("non-TTY logout was not gated: exit=%d called=%t output=%q", code, clientCalled, out.String())
	}
}

func TestSecretRequiresExplicitRegistry(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\n")}
	if code := runner.Run(context.Background(), []string{"secret", "set"}); code != 2 {
		t.Fatalf("secret set without service or registry: exit=%d", code)
	}
}

func TestSecretHelpAndAlias(t *testing.T) {
	for _, name := range []string{"secret", "secrets"} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{name, "--help"}); code != 0 {
			t.Fatalf("%s --help: exit=%d, output=%q", name, code, out.String())
		}
		if !strings.Contains(out.String(), "service secrets and registry credentials") {
			t.Fatalf("missing current limitation: %q", out.String())
		}
	}
}

func TestSecretCustomFailsClosedAndImportHelpIsAvailable(t *testing.T) {
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output}
	if code := runner.Run(context.Background(), []string{"secret", "set-custom", "--host", "api.example.invalid", "--value", "synthetic"}); code != 1 {
		t.Fatalf("set-custom exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "no secret was stored") {
		t.Fatalf("set-custom did not explain fail-closed result: %q", output.String())
	}

	output.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "set-custom", "--help"}); code != 0 {
		t.Fatalf("set-custom help exit=%d output=%q", code, output.String())
	}
	for _, expected := range []string{"Status:", "Unsupported.", "--host", "will not store or inject"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("set-custom help lacks %q: %s", expected, output.String())
		}
	}

	output.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "import", "--help"}); code != 0 {
		t.Fatalf("import help exit=%d output=%q", code, output.String())
	}
	for _, expected := range []string{"Usage:", "--dry-run", "--force", "without prompting"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("import help lacks %q: %s", expected, output.String())
		}
	}
}

func TestSecretListHelpMatchesSupportedFilterSurface(t *testing.T) {
	for _, command := range []string{"ls", "list"} {
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output}
		if code := runner.Run(context.Background(), []string{"secret", command, "--help"}); code != 0 {
			t.Fatalf("%s help exit=%d output=%q", command, code, output.String())
		}
		for _, expected := range []string{"Aliases:", "ls, list", "--global", "--sandbox", "--service", "--quiet", "--format", "--json"} {
			if !strings.Contains(output.String(), expected) {
				t.Errorf("%s help lacks %q: %s", command, expected, output.String())
			}
		}
	}
}

type fakeClient struct {
	registry        *fakeRegistryCredentials
	secrets         sdk.SecretService
	sandbox         sdk.SandboxService
	operations      sdk.OperationService
	accounts        sdk.AccountService
	interactive     sdk.InteractiveAccountService
	dockerPAT       sdk.DockerPATAccountService
	accountStatuses sdk.AccountStatusService
}

func (f fakeClient) DockerPATAccountService() sdk.DockerPATAccountService {
	if f.dockerPAT == nil {
		return nil
	}
	return f.dockerPAT
}

type fakeDockerPATAccounts struct {
	username string
	password []byte
}

func (f *fakeDockerPATAccounts) LoginWithPAT(_ context.Context, username string, password []byte) error {
	f.username = username
	f.password = append(f.password[:0], password...)
	return nil
}

func (f fakeClient) Sandboxes() sdk.SandboxService {
	if f.sandbox != nil {
		return f.sandbox
	}
	return fakeSandbox{}
}
func (f fakeClient) Operations() sdk.OperationService {
	if f.operations != nil {
		return f.operations
	}
	return fakeOperations{}
}
func (f fakeClient) RegistryCredentials() sdk.RegistryCredentialService {
	if f.registry == nil {
		return &fakeRegistryCredentials{}
	}
	return f.registry
}
func (f fakeClient) ListRegistryCredentials(context.Context) ([]sdk.RegistryCredentialSummary, error) {
	if f.registry == nil {
		return nil, nil
	}
	return f.registry.items, f.registry.listErr
}
func (f fakeClient) SecretService() sdk.SecretService { return f.secrets }
func (f fakeClient) AccountService() sdk.AccountService {
	if f.accounts == nil {
		return nil
	}
	return f.accounts
}
func (f fakeClient) AccountStatusService() sdk.AccountStatusService {
	if f.accountStatuses != nil {
		return f.accountStatuses
	}
	return fakeAccountStatus{}
}
func (f fakeClient) InteractiveAccountService() sdk.InteractiveAccountService {
	if f.interactive != nil {
		return f.interactive
	}
	if f.accounts == nil {
		return nil
	}
	return fakeInteractiveAccounts{accounts: f.accounts}
}
func (fakeClient) Close() error { return nil }

type fakeInteractiveAccounts struct{ accounts sdk.AccountService }

type interactiveAccountFunc func(context.Context, string, func(context.Context, sdk.DeviceLoginInfo) error) error

func (f interactiveAccountFunc) LoginInteractive(ctx context.Context, provider string, handoff func(context.Context, sdk.DeviceLoginInfo) error) error {
	return f(ctx, provider, handoff)
}

func (f fakeInteractiveAccounts) LoginInteractive(ctx context.Context, provider string, handoff func(context.Context, sdk.DeviceLoginInfo) error) error {
	if err := handoff(ctx, sdk.DeviceLoginInfo{UserCode: "ABCD-EFGH", VerificationURI: "https://login.example/device"}); err != nil {
		return err
	}
	return f.accounts.Login(ctx, provider)
}

type fakeAccounts struct{}

type fakeAccountStatus struct {
	statuses map[string]bool
	err      error
}

func (f fakeAccountStatus) Status(_ context.Context, provider string) (bool, error) {
	return f.statuses[provider], f.err
}

func (fakeAccounts) Login(_ context.Context, provider string) error {
	if provider != "docker" && provider != "openai" {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (fakeAccounts) Logout(_ context.Context, provider string) (bool, error) {
	return provider == "docker" || provider == "openai", nil
}

type fakeRegistryCredentials struct {
	request  sdk.RegistryLoginRequest
	password string
	requests []sdk.RegistryLogoutRequest
	items    []sdk.RegistryCredentialSummary
	listErr  error
}

func (f *fakeRegistryCredentials) Login(_ context.Context, req sdk.RegistryLoginRequest) (*sdk.RegistryLoginResponse, error) {
	f.password = string(req.Password)
	f.request = req
	return &sdk.RegistryLoginResponse{Registry: req.Registry, Username: req.Username, Scope: req.Scope, SandboxName: req.SandboxName}, nil
}

func (f *fakeRegistryCredentials) Logout(_ context.Context, req sdk.RegistryLogoutRequest) (*sdk.RegistryLogoutResponse, error) {
	f.requests = append(f.requests, req)
	return &sdk.RegistryLogoutResponse{Removed: req.Registry == "ghcr.io"}, nil
}

type fakeSandbox struct{}

type logoutSandbox struct {
	fakeSandbox
	stops int
}

func (*logoutSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-run", Name: "owned", State: sdk.StateRunning}}}, nil
}

func (s *logoutSandbox) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	if id != "sb-run" {
		return nil, io.ErrUnexpectedEOF
	}
	s.stops++
	return &sdk.Operation{ID: "op-stop", Kind: "stop", State: sdk.StateDone}, nil
}

type pagedSandbox struct {
	fakeSandbox
	cycle bool
}

func (s pagedSandbox) List(_ context.Context, opts sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	if opts.PageToken == "" {
		return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{Name: "first"}}, NextPageToken: "next"}, nil
	}
	page := &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{Name: "second"}}}
	if s.cycle {
		page.NextPageToken = "next"
	}
	return page, nil
}

func (fakeSandbox) Create(context.Context, sdk.CreateRequest) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", Kind: "create", State: "done"}, nil
}
func (fakeSandbox) Get(context.Context, string) (*sdk.Sandbox, error) {
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", State: "stopped"}, nil
}
func (fakeSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "stopped"}}}, nil
}
func (fakeSandbox) Start(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-2", Kind: "start", State: "done"}, nil
}
func (fakeSandbox) Stop(context.Context, string, sdk.StopOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-3", Kind: "stop", State: "done"}, nil
}
func (fakeSandbox) Delete(context.Context, string, sdk.DeleteOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-4", Kind: "delete", State: "done"}, nil
}
func (fakeSandbox) Watch(context.Context, sdk.WatchOptions) (sdk.EventStream, error) {
	return fakeEventStream{}, nil
}

type fakeEventStream struct{}

func (fakeEventStream) Recv() (*sdk.Event, error) { return nil, io.EOF }
func (fakeEventStream) Close() error              { return nil }

type fakeOperations struct{}

type failedOperations struct{ fakeOperations }

func (failedOperations) Wait(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: sdk.StateFailed}, nil
}

func (fakeOperations) Get(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}
func (fakeOperations) Wait(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}

func TestGetResolvesSandboxName(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"get", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "id: sb-1") || !strings.Contains(out.String(), "cpus:") {
		t.Fatalf("unexpected get output: %q", out.String())
	}
}
