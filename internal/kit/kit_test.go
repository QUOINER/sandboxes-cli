package kit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeLocalKit(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: codex-go}
spec:
  agent: codex
  policy_profile: sbx-compat
  mounts:
    - {path: /work, read_only: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != "codex-go" || doc.Spec.Agent != "codex" || len(doc.Paths()) != 1 || doc.Paths()[0] != "/work:ro" {
		t.Fatalf("doc=%+v paths=%v", doc, doc.Paths())
	}
}

func TestDecodeOpenAIOAuthCredential(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: codex-oauth}
spec:
  agent: codex
  credentials:
    - service: openai
      oauth:
        resourceHosts: [api.openai.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.OAuthEnvironment(); len(got) != 1 || got[0] != "OPENAI_API_KEY=${oauth:openai}" {
		t.Fatalf("OAuth environment=%q", got)
	}
	for _, hosts := range []string{"[attacker.invalid]", "[api.openai.com, chatgpt.com]"} {
		body := "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata: {name: invalid}\nspec:\n  agent: codex\n  credentials:\n    - service: openai\n      oauth:\n        resourceHosts: " + hosts + "\n"
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Errorf("accepted untrusted OAuth resources %s", hosts)
		}
	}
	if _, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: openai-default-host}
spec: {agent: codex, credentials: [{service: openai, oauth: {}}]}
`)); err != nil {
		t.Fatalf("omitted Docker-optional resourceHosts rejected: %v", err)
	}
	custom := `apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: invalid}
spec: {agent: codex, credentials: [{service: openai, oauth: {resourceHosts: [api.openai.com], tokenEndpoint: {host: auth.example.test, path: /token}}}]}
`
	if _, err := Decode(strings.NewReader(custom)); err == nil {
		t.Fatal("accepted a kit override for the fixed OpenAI issuer")
	}
}

func TestDecodeGenericOAuthKitDeclaration(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: fixture-oauth}
spec:
  agent: codex
  credentials:
    - service: fixture
      oauth:
        tokenEndpoint: {host: auth.example.test, path: /oauth/token}
        resourceHosts: [api.example.test]
        sentinels: {accessToken: ACCESS_SENTINEL, refreshToken: REFRESH_SENTINEL}
        credentialFile:
          path: ~/.fixture/credentials.json
          structure: {access_token: "{{.AccessToken}}"}
        responseFields: {accessToken: access_token, refreshToken: refresh_token, expiresIn: expires_in}
        skipIfEnv: [FIXTURE_TOKEN]
`))
	if err != nil {
		t.Fatal(err)
	}
	credential := doc.Spec.Credentials[0]
	if credential.Service != "fixture" || credential.OAuth.TokenEndpoint == nil || credential.OAuth.TokenEndpoint.Host != "auth.example.test" || credential.OAuth.CredentialFile == nil || credential.OAuth.CredentialFile.Path != "~/.fixture/credentials.json" || credential.OAuth.ResponseFields == nil || credential.OAuth.ResponseFields.AccessToken != "access_token" {
		t.Fatalf("decoded OAuth credential=%+v", credential)
	}
	if got := doc.OAuthEnvironment(); len(got) != 0 {
		t.Fatalf("v2 skipIfEnv is schema-only and must not inject environment values: %q", got)
	}
	for _, invalid := range []string{
		"tokenEndpoint: {host: auth.example.test, path: /../token}",
	} {
		body := strings.Replace(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: fixture-oauth}
spec: {agent: codex, credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /oauth/token}, resourceHosts: [api.example.test], sentinels: {accessToken: ACCESS_SENTINEL, refreshToken: REFRESH_SENTINEL}}}]}
`, "refreshTokenSentinel: REFRESH_SENTINEL", "refreshTokenSentinel: REFRESH_SENTINEL, "+invalid, 1)
		if invalid == "tokenEndpoint: {host: auth.example.test, path: /../token}" {
			body = `apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: fixture-oauth}
spec: {agent: codex, credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /../token}, sentinels: {accessToken: A, refreshToken: B}}}]}
`
		}
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Errorf("accepted invalid OAuth field %q", invalid)
		}
	}
}

func TestDecodePassthroughOAuthLeavesSentinelsAbsent(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: passthrough}
spec: {agent: codex, credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	credential := doc.Spec.Credentials[0].OAuth
	if credential.Sentinels != nil {
		t.Fatalf("omitted passthrough sentinels were materialized: %+v", credential.Sentinels)
	}
}

func TestDecodeRejectsEmptyOAuthCredentialFile(t *testing.T) {
	_, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: empty-credential-file}
spec: {agent: codex, credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true, credentialFile: {}}}]}
`))
	if err == nil || !strings.Contains(err.Error(), "credentialFile.path is required") {
		t.Fatalf("empty credentialFile should be rejected like sbx: %v", err)
	}
}

func TestDecodePreservesEmptyPassthroughOAuthMessages(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: empty-passthrough-messages}
spec: {agent: codex, credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true, sentinels: {}, responseFields: {}}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	oauth := doc.Spec.Credentials[0].OAuth
	if oauth.Sentinels == nil || oauth.ResponseFields == nil || oauth.CredentialFile != nil {
		t.Fatalf("explicit empty OAuth messages lost their presence: %+v", oauth)
	}
}

func TestDecodeDockerV2OAuthKit(t *testing.T) {
	doc, err := Decode(strings.NewReader(`schemaVersion: "2"
kind: sandbox
name: fixture
sandbox: {image: ubuntu:latest}
credentials:
  - service: fixture
    oauth:
      tokenEndpoint: {host: auth.example.test, path: /oauth/token}
      resourceHosts: [api.example.test]
      sentinels: {accessToken: ACCESS_SENTINEL, refreshToken: REFRESH_SENTINEL}
      credentialFile:
        path: ~/.fixture/credentials.json
        structure: {access_token: "{{.AccessToken}}"}
        template: '{"token":"{{.AccessToken}}"}'
      responseFields: {accessToken: access_token, refreshToken: refresh_token, expiresIn: expires_in}
      skipIfEnv: [FIXTURE_TOKEN]
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != "fixture" || doc.Spec.Image != "ubuntu:latest" || doc.Spec.Credentials[0].OAuth.Sentinels == nil || doc.Spec.Credentials[0].OAuth.Sentinels.AccessToken != "ACCESS_SENTINEL" {
		t.Fatalf("Docker v2 kit was not mapped: %+v", doc)
	}
	for _, body := range []string{
		`schemaVersion: "2"\nkind: sandbox\nname: p\nsandbox: {image: ubuntu}\ncredentials: [{service: p, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true}}]`,
		`schemaVersion: "2"\nkind: sandbox\nname: p\nsandbox: {image: ubuntu}\ncredentials: [{service: p, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true, credentialFile: {path: ~/.p/tokens.json, structure: {token: "{{.AccessToken}}"}, template: "ignored"}}}]`,
	} {
		if _, err := Decode(strings.NewReader(strings.ReplaceAll(body, `\n`, "\n"))); err != nil {
			t.Errorf("valid Docker v2 form rejected: %v", err)
		}
	}
	unsupported := `schemaVersion: "2"
kind: sandbox
name: fixture
sandbox: {image: ubuntu}
unexpected: true
`
	if _, err := Decode(strings.NewReader(unsupported)); err == nil {
		t.Fatal("accepted unsupported Docker v2 field")
	}
}

func TestDecodeDockerV2AcceptsNumericSchemaVersion(t *testing.T) {
	for _, value := range []string{"2", `"2"`} {
		input := "schemaVersion: " + value + "\nkind: sandbox\nname: version\nsandbox: {image: ubuntu:latest}\n"
		if _, err := Decode(strings.NewReader(input)); err != nil {
			t.Errorf("Docker v2 schemaVersion %s rejected: %v", value, err)
		}
	}
}

func TestLoadDockerV2KitDirectory(t *testing.T) {
	for _, filename := range []string{"spec.yaml", "spec.yml"} {
		directory := t.TempDir()
		body := `schemaVersion: "2"
kind: sandbox
name: from-directory
sandbox: {image: ubuntu:latest}
`
		if err := os.WriteFile(filepath.Join(directory, filename), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		doc, err := Load(directory)
		if err != nil || doc.Metadata.Name != "from-directory" {
			t.Fatalf("Load(%q) doc=%+v err=%v", filename, doc, err)
		}
	}
}

func TestLoadDockerV2DirectoryPrefersSpecYAML(t *testing.T) {
	directory := t.TempDir()
	for name, kitName := range map[string]string{"spec.yaml": "preferred", "spec.yml": "fallback"} {
		body := "schemaVersion: 2\nkind: sandbox\nname: " + kitName + "\nsandbox: {image: ubuntu:latest}\n"
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := Load(directory)
	if err != nil || doc.Metadata.Name != "preferred" {
		t.Fatalf("Load(directory) name=%q err=%v", doc.Metadata.Name, err)
	}
}

func TestOAuthHostSchemaAcceptanceMatchesDockerSubset(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "a..example.test", "-bad.example.test", "bad-.example.test"} {
		if !validOAuthHost(host) {
			t.Errorf("rejected host accepted by Docker kit schema %q", host)
		}
	}
	for _, host := range []string{"", "a/../b", "https://auth.example.test", "auth.example.test:443"} {
		if validOAuthHost(host) {
			t.Errorf("accepted a non-host value %q", host)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: fuzz-seed}
spec: {agent: shell}
`)
	f.Add(`schemaVersion: "2"
kind: sandbox
name: fuzz-v2
sandbox: {image: ubuntu:latest}
credentials: [{service: fixture, oauth: {tokenEndpoint: {host: auth.example.test, path: /token}, passthrough: true}}]
`)
	f.Add("\x00\xffnot yaml")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = Decode(strings.NewReader(input))
	})
}

func TestDecodeRejectsUnsupportedAndUnknown(t *testing.T) {
	for _, body := range []string{
		"apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, mcp: {allow: [github]}}\n",
		"apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, unknown: true}\n",
		"apiVersion: v1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex}\n",
	} {
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}

func TestSeedValidation(t *testing.T) {
	for _, seed := range []string{
		"https://github.com/example/repo.git",
		"ssh://git@example.com/repo.git",
		"git@example.com:repo.git",
	} {
		if err := validateSeed(seed); err != nil {
			t.Fatalf("rejected %q: %v", seed, err)
		}
	}
	for _, seed := range []string{
		"file:///tmp/repo", "-u", "repo", "https://example.com/a b", "git@example.com",
	} {
		if err := validateSeed(seed); err == nil {
			t.Fatalf("accepted %q", seed)
		}
	}
}

func TestDecodeSeedKit(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: seeded}
spec:
  agent: codex
  workspace: {seed: "https://github.com/example/repo.git"}
`))
	if err != nil || doc.Spec.Workspace.Seed == "" {
		t.Fatalf("doc=%+v err=%v", doc, err)
	}
}

func TestResolveSeedUsesExistingCache(t *testing.T) {
	seed := "https://github.com/example/repo.git"
	sum := sha256.Sum256([]byte(seed))
	cache := t.TempDir()
	dest := filepath.Join(cache, hex.EncodeToString(sum[:12]))
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSeed(context.Background(), seed, cache)
	if err != nil || got != dest {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
