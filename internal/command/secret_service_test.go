package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/QUOINER/sandboxes-go-sdk"
)

type fakeServiceSecrets struct {
	service string
	scope   sdk.SecretScope
	name    string
	value   []byte
}

func (f *fakeServiceSecrets) Set(_ context.Context, service string, scope sdk.SecretScope, name string, value []byte) (sdk.ServiceSecret, error) {
	f.service, f.scope, f.name = service, scope, name
	f.value = append(f.value[:0], value...)
	return sdk.ServiceSecret{Service: service, Scope: scope, SandboxName: name}, nil
}

func (*fakeServiceSecrets) List(context.Context) ([]sdk.ServiceSecret, error) { return nil, nil }
func (*fakeServiceSecrets) Remove(context.Context, string, sdk.SecretScope, string) (bool, error) {
	return false, nil
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
