package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type fakeServiceSecrets struct {
	service     string
	scope       sdk.SecretScope
	name        string
	value       []byte
	items       []sdk.ServiceSecret
	listErr     error
	createCalls int
	createErr   error
	removed     []sdk.ServiceSecret
	removeErr   error
	removeErrAt int
	removeCalls int
	removeCount int
}

type recordingAccounts struct {
	loggedOut []string
	removed   bool
	err       error
}

func (*recordingAccounts) Login(context.Context, string) error { return nil }
func (f *recordingAccounts) Logout(_ context.Context, provider string) (bool, error) {
	f.loggedOut = append(f.loggedOut, provider)
	return f.removed, f.err
}

func TestSecretRemoveOpenAIAlsoRemovesGlobalOAuthCredential(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	accounts := &recordingAccounts{removed: true}
	client := fakeClient{secrets: secrets, accounts: accounts}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "openai", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 1 || secrets.removed[0].Scope != sdk.SecretScopeGlobal {
		t.Fatalf("API-key removal=%+v", secrets.removed)
	}
	if len(accounts.loggedOut) != 1 || accounts.loggedOut[0] != "openai" {
		t.Fatalf("OAuth logout calls=%v", accounts.loggedOut)
	}
	if !strings.Contains(out.String(), "Removed openai credentials") {
		t.Fatalf("unexpected output=%q", out.String())
	}
}

func TestSecretSetOAuthWithoutServiceUsesOpenAIProvider(t *testing.T) {
	client := fakeClient{accounts: fakeAccounts{}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "set", "--oauth"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "Stored openai OAuth credentials") {
		t.Fatalf("OAuth provider was not selected: %q", out.String())
	}
}

func TestSecretSetTokenShortFlag(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	client := fakeClient{secrets: secrets}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "set", "github", "-t", "synthetic-token"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if secrets.service != "github" || string(secrets.value) != "synthetic-token" {
		t.Fatalf("stored service=%q value=%q", secrets.service, secrets.value)
	}
}

func TestSecretRemoveSandboxOpenAIDoesNotRemoveGlobalOAuth(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	accounts := &recordingAccounts{removed: true}
	client := fakeClient{secrets: secrets, accounts: accounts}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "openai", "--sandbox", "dev", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 1 || secrets.removed[0].Scope != sdk.SecretScopeSandbox || secrets.removed[0].SandboxName != "dev" {
		t.Fatalf("sandbox API-key removal=%+v", secrets.removed)
	}
	if len(accounts.loggedOut) != 0 {
		t.Fatalf("sandbox removal unexpectedly logged out global account: %v", accounts.loggedOut)
	}
}

func TestSecretRemoveOpenAIReportsPartialOAuthRevocationFailure(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	accounts := &recordingAccounts{err: errors.New("synthetic revocation failure")}
	client := fakeClient{secrets: secrets, accounts: accounts}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "openai", "--force"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 1 || !strings.Contains(out.String(), "Removed openai API key, but OAuth credential removal failed") {
		t.Fatalf("partial result not reported: removed=%+v output=%q", secrets.removed, out.String())
	}
}

func (f *fakeServiceSecrets) Set(_ context.Context, service string, scope sdk.SecretScope, name string, value []byte) (sdk.ServiceSecret, error) {
	f.service, f.scope, f.name = service, scope, name
	f.value = append(f.value[:0], value...)
	return sdk.ServiceSecret{Service: service, Scope: scope, SandboxName: name}, nil
}

func (f *fakeServiceSecrets) Create(ctx context.Context, service string, scope sdk.SecretScope, name string, value []byte) (sdk.ServiceSecret, error) {
	f.createCalls++
	if f.createErr != nil {
		return sdk.ServiceSecret{}, f.createErr
	}
	for _, item := range f.items {
		if item.Service == service && item.Scope == scope && item.SandboxName == name {
			return sdk.ServiceSecret{}, &sdk.Error{Code: "already_exists", Message: "service secret already exists; pass --force to replace it"}
		}
	}
	return f.Set(ctx, service, scope, name, value)
}

func (f *fakeServiceSecrets) List(context.Context) ([]sdk.ServiceSecret, error) {
	return f.items, f.listErr
}
func (f *fakeServiceSecrets) Remove(_ context.Context, service string, scope sdk.SecretScope, name string) (bool, error) {
	f.removeCalls++
	f.removed = append(f.removed, sdk.ServiceSecret{Service: service, Scope: scope, SandboxName: name})
	if f.removeErr != nil && f.removeCalls == f.removeErrAt {
		return false, f.removeErr
	}
	f.removeCount++
	return true, nil
}

func TestSecretRemoveAllClearsSupportedScopesAndAccounts(t *testing.T) {
	secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{
		{Service: "openai", Scope: sdk.SecretScopeGlobal},
		{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
	}}
	registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{
		{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
		{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
	}}
	client := fakeClient{secrets: secrets, registry: registry, accounts: fakeAccounts{}, accountStatuses: fakeAccountStatus{statuses: map[string]bool{"docker": true, "openai": true}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--all", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 2 || len(registry.requests) != 2 {
		t.Fatalf("removed service/registry entries=%d/%d output=%q", len(secrets.removed), len(registry.requests), out.String())
	}
	if !strings.Contains(out.String(), "Removed 6 inventoried Rheic-managed host credentials") {
		t.Fatalf("unexpected output=%q", out.String())
	}
	if !strings.Contains(out.String(), "Custom-secret storage is unavailable") {
		t.Fatalf("missing partial-support disclosure: %q", out.String())
	}
}

func TestSecretRemoveAllFailsBeforeMutationWhenInventoryFails(t *testing.T) {
	secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: "openai", Scope: sdk.SecretScopeGlobal}}}
	registry := &fakeRegistryCredentials{listErr: errors.New("synthetic registry inventory failure")}
	client := fakeClient{secrets: secrets, registry: registry, accounts: fakeAccounts{}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--all", "--force"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 0 || len(registry.requests) != 0 {
		t.Fatalf("inventory failure mutated credentials: service=%d registry=%d", len(secrets.removed), len(registry.requests))
	}
}

func TestSecretRemoveAllStopsAfterPartialRemovalFailure(t *testing.T) {
	secrets := &fakeServiceSecrets{
		items: []sdk.ServiceSecret{
			{Service: "openai", Scope: sdk.SecretScopeGlobal},
			{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
		},
		removeErr: errors.New("synthetic delete failure"), removeErrAt: 2,
	}
	registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)}}}
	client := fakeClient{secrets: secrets, registry: registry, accounts: fakeAccounts{}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--all", "--force"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if secrets.removeCount != 1 || registry.requests != nil || !strings.Contains(out.String(), "partial credential removal after 1 entries") {
		t.Fatalf("partial deletion handling: removed=%d registry=%v output=%q", secrets.removeCount, registry.requests, out.String())
	}
}

func TestServiceSecretSetReportsHostKeychainStorage(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	client := fakeClient{secrets: secrets}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "set", "openai", "--token", "synthetic-secret"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if secrets.service != "openai" || secrets.scope != sdk.SecretScopeGlobal || string(secrets.value) != "synthetic-secret" {
		t.Fatalf("stored service=%q scope=%q value=%q", secrets.service, secrets.scope, secrets.value)
	}
	if !strings.Contains(out.String(), "Stored openai secret (global) in host keychain") || strings.Contains(out.String(), "not injected into sandboxes") || strings.Contains(out.String(), "synthetic-secret") {
		t.Fatalf("unexpected output=%q", out.String())
	}
}

func TestServiceSecretSetRequiresForceToOverwriteTokenValue(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "without force", args: []string{"secret", "set", "openai", "--token", "replacement"}, want: 2},
		{name: "with force", args: []string{"secret", "set", "openai", "--token", "replacement", "-f"}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: "openai", Scope: sdk.SecretScopeGlobal}}}
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
				return fakeClient{secrets: secrets}, nil
			}}
			if code := runner.Run(context.Background(), test.args); code != test.want {
				t.Fatalf("exit=%d output=%q want=%d", code, out.String(), test.want)
			}
			if test.want == 2 && secrets.value != nil {
				t.Fatalf("secret was written without --force: %q", secrets.value)
			}
			if test.want == 0 && string(secrets.value) != "replacement" {
				t.Fatalf("secret was not overwritten: %q", secrets.value)
			}
			if strings.Contains(out.String(), "replacement") {
				t.Fatalf("output disclosed secret: %q", out.String())
			}
		})
	}
}

func TestServiceSecretSetFailsClosedWhenCreateRequestFails(t *testing.T) {
	secrets := &fakeServiceSecrets{createErr: errors.New("synthetic create failure")}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
		return fakeClient{secrets: secrets}, nil
	}}
	if code := runner.Run(context.Background(), []string{"secret", "set", "openai", "--token", "replacement"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if secrets.value != nil || !strings.Contains(out.String(), "synthetic create failure") || strings.Contains(out.String(), "replacement") {
		t.Fatalf("write did not fail closed or output disclosed token: value=%q output=%q", secrets.value, out.String())
	}
}
