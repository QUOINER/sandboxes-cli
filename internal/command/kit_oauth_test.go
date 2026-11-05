package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-cli/internal/kit"
)

func TestKitInspectMatchesDockerDirectoryFlagGrammar(t *testing.T) {
	directory := t.TempDir()
	spec := `schemaVersion: 2
kind: sandbox
name: cli-inspect
sandbox: {image: ubuntu:latest}
`
	if err := os.WriteFile(filepath.Join(directory, "spec.yaml"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Out: &stdout, Err: &stderr}
	code := runner.Run(context.Background(), []string{"kit", "inspect", directory, "--format", "json"})
	if code != 0 || !strings.Contains(stdout.String(), `"Name": "cli-inspect"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestConvertOAuthCredentialsPreservesKitBrokerContract(t *testing.T) {
	credentials := []kit.Credential{{Service: "fixture", OAuth: &kit.OAuthCredential{
		TokenEndpoint: kit.TokenEndpoint{Host: "auth.example.test", Path: "/oauth/token"},
		ResourceHosts: []string{"api.example.test"}, Sentinels: kit.Sentinels{AccessToken: "ACCESS_SENTINEL", RefreshToken: "REFRESH_SENTINEL"},
		CredentialFile: kit.CredentialFile{Path: "/home/agent/.fixture/credentials.json", Structure: map[string]any{"access_token": "{{.AccessToken}}"}, Template: `{"token":"{{.AccessToken}}"}`},
		ResponseFields: kit.ResponseFields{AccessToken: "access_token", RefreshToken: "refresh_token", ExpiresIn: "expires_in"},
	}}}
	got, err := convertOAuthCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("credentials=%+v", got)
	}
	credential := got[0]
	if credential.Service != "fixture" || credential.TokenEndpoint.Host != "auth.example.test" || credential.TokenEndpoint.Path != "/oauth/token" ||
		credential.CredentialFile.Path != "/home/agent/.fixture/credentials.json" || credential.ResponseFields.AccessToken != "access_token" || credential.ResponseFields.ExpiresIn != "expires_in" || credential.CredentialFile.StructureJSON != `{"access_token":"{{.AccessToken}}"}` || credential.CredentialFile.Template != `{"token":"{{.AccessToken}}"}` {
		t.Fatalf("converted OAuth declaration=%+v", credential)
	}
}

func TestConvertOAuthCredentialsKeepsOpenAIProviderDaemonManaged(t *testing.T) {
	credentials := []kit.Credential{{Service: "openai", OAuth: &kit.OAuthCredential{TokenEndpoint: kit.TokenEndpoint{Host: "attacker.example", Path: "/token"}}}}
	got, err := convertOAuthCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("OpenAI kit overrode fixed daemon provider config: %+v", got)
	}
}
