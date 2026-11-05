package command

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type secretListClient struct {
	fakeClient
	items []sdk.RegistryCredentialSummary
}

func (s secretListClient) ListRegistryCredentials(context.Context) ([]sdk.RegistryCredentialSummary, error) {
	return s.items, nil
}

func TestSecretList(t *testing.T) {
	client := secretListClient{
		fakeClient: fakeClient{secrets: &fakeServiceSecrets{items: []sdk.ServiceSecret{{Service: "openai", Scope: sdk.SecretScopeGlobal}}}},
		items:      []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Username: "alice", Scope: "sandbox", SandboxName: "dev"}},
	}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("ghcr.io")) || bytes.Contains(out.Bytes(), []byte("password")) {
		t.Fatalf("output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "ls", "--json"}); code != 0 {
		t.Fatalf("json exit=%d", code)
	}
	var items []serviceSecretOutput
	if err := json.Unmarshal(out.Bytes(), &items); err != nil || len(items) != 2 || items[1].Username != "alice" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
}

func TestSecretListFiltersAndQuietOutput(t *testing.T) {
	client := secretListClient{
		fakeClient: fakeClient{secrets: &fakeServiceSecrets{items: []sdk.ServiceSecret{
			{Service: "openai", Scope: sdk.SecretScopeGlobal},
			{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
		}}},
		items: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
			{Registry: "quay.io", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
		},
	}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "ls", "-q", "--service", "openai", "-g"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if got := out.String(); got != "openai\n" {
		t.Fatalf("quiet filtered output=%q, want only global openai", got)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "ls", "--sandbox", "dev", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var listed []serviceSecretOutput
	if err := json.Unmarshal(out.Bytes(), &listed); err != nil || len(listed) != 2 {
		t.Fatalf("sandbox filtered items=%+v err=%v output=%s", listed, err, out.String())
	}
}

func TestSecretListAlias(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		return secretListClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"secret", "list"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("No secrets stored")) {
		t.Fatalf("output=%q", out.String())
	}
}

func TestSecretListEmpty(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return secretListClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("No secrets stored")) {
		t.Fatalf("output=%q", out.String())
	}
}
