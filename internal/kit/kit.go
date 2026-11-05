// Package kit parses local Rheic kit files.
package kit

import (
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kit is a local, unsigned kit definition. Remote OCI kits and signatures are
// deliberately out of scope for this parser.
type Kit struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// dockerV2Kit is the deliberately supported Docker Sandboxes v2 subset.
// Unsupported fields are rejected instead of silently ignored.
type dockerV2Kit struct {
	SchemaVersion string `yaml:"schemaVersion"`
	Kind          string `yaml:"kind"`
	Name          string `yaml:"name"`
	Sandbox       struct {
		Image string `yaml:"image"`
	} `yaml:"sandbox"`
	Credentials []Credential `yaml:"credentials"`
}

// Metadata identifies a kit.
type Metadata struct {
	Name string `yaml:"name"`
}

// Spec is the runnable kit configuration.
type Spec struct {
	Agent         string       `yaml:"agent"`
	Image         string       `yaml:"image"`
	PolicyProfile string       `yaml:"policy_profile"`
	Workspace     Workspace    `yaml:"workspace"`
	MCP           MCP          `yaml:"mcp"`
	Mounts        []Mount      `yaml:"mounts"`
	Credentials   []Credential `yaml:"credentials"`
}

// Credential is the supported OAuth credential declaration subset.
type Credential struct {
	Service string           `yaml:"service"`
	OAuth   *OAuthCredential `yaml:"oauth"`
}

// OAuthCredential declares one fixed resource-host broker route. The daemon
// owns provider endpoints and token handling; kits cannot override them.
type OAuthCredential struct {
	TokenEndpoint  *TokenEndpoint  `yaml:"tokenEndpoint"`
	ResourceHosts  []string        `yaml:"resourceHosts"`
	Sentinels      *Sentinels      `yaml:"sentinels"`
	CredentialFile *CredentialFile `yaml:"credentialFile"`
	ResponseFields *ResponseFields `yaml:"responseFields"`
	Passthrough    bool            `yaml:"passthrough"`
	SkipIfEnv      []string        `yaml:"skipIfEnv"`
}

type Sentinels struct {
	AccessToken  string `yaml:"accessToken"`
	RefreshToken string `yaml:"refreshToken"`
}

type TokenEndpoint struct {
	Host string `yaml:"host"`
	Path string `yaml:"path"`
}
type CredentialFile struct {
	Path      string         `yaml:"path"`
	Structure map[string]any `yaml:"structure"`
	Template  string         `yaml:"template"`
}
type ResponseFields struct {
	AccessToken  string `yaml:"accessToken"`
	RefreshToken string `yaml:"refreshToken"`
	ExpiresIn    string `yaml:"expiresIn"`
	Scope        string `yaml:"scope"`
	IDToken      string `yaml:"idToken"`
}

// Workspace is a first-start workspace seed. Seed is not implemented yet and
// must be empty so a kit cannot silently skip its checkout.
type Workspace struct {
	Seed string `yaml:"seed"`
}

// MCP is an MCP allowlist. It is parsed but not applied until the MCP gateway
// exists, so a non-empty allowlist fails closed.
type MCP struct {
	Allow []string `yaml:"allow"`
}

// Mount is an additional host workspace.
type Mount struct {
	Path     string `yaml:"path"`
	ReadOnly bool   `yaml:"read_only"`
}

// Load reads one local kit file with unknown fields rejected.
func Load(path string) (Kit, error) {
	info, err := os.Stat(path) // #nosec G304 -- user-selected local kit reference
	if err != nil {
		return Kit{}, fmt.Errorf("inspect kit reference: %w", err)
	}
	if info.IsDir() {
		path, err = findKitSpec(path)
		if err != nil {
			return Kit{}, err
		}
	}
	file, err := os.Open(path) // #nosec G304 -- user-selected local kit path
	if err != nil {
		return Kit{}, fmt.Errorf("open kit: %w", err)
	}
	defer func() { _ = file.Close() }()
	return Decode(file)
}

func findKitSpec(directory string) (string, error) {
	for _, name := range []string{"spec.yaml", "spec.yml"} {
		candidate := filepath.Join(directory, name)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect kit spec: %w", err)
		}
	}
	return "", errors.New("kit directory requires spec.yaml or spec.yml")
}

// Decode parses a kit from r.
func Decode(r io.Reader) (Kit, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return Kit{}, fmt.Errorf("read kit: %w", err)
	}
	if len(data) > 1<<20 {
		return Kit{}, errors.New("kit exceeds 1 MiB")
	}
	var header struct {
		SchemaVersion string `yaml:"schemaVersion"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return Kit{}, fmt.Errorf("parse kit: %w", err)
	}
	doc, err := decodeDockerOrLocal(data, header.SchemaVersion)
	if err != nil {
		return Kit{}, err
	}
	if err := doc.Validate(); err != nil {
		return Kit{}, err
	}
	return doc, nil
}

func decodeDockerOrLocal(data []byte, schemaVersion string) (Kit, error) {
	if schemaVersion == "2" {
		return decodeDockerV2(data)
	}
	var doc Kit
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return Kit{}, fmt.Errorf("parse kit: %w", err)
	}
	return doc, nil
}

func decodeDockerV2(data []byte) (Kit, error) {
	var source dockerV2Kit
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&source); err != nil {
		return Kit{}, fmt.Errorf("parse Docker v2 kit: %w", err)
	}
	if source.Kind != "sandbox" {
		return Kit{}, fmt.Errorf("unsupported Docker v2 kit kind %q", source.Kind)
	}
	return Kit{APIVersion: "rheic.dev/v1alpha1", Kind: "Kit", Metadata: Metadata{Name: source.Name},
		Spec: Spec{Image: source.Sandbox.Image, Credentials: source.Credentials}}, nil
}

// Validate checks the stable local subset.
func (k Kit) Validate() error {
	if k.APIVersion != "rheic.dev/v1alpha1" {
		return fmt.Errorf("unsupported kit apiVersion %q", k.APIVersion)
	}
	if k.Kind != "Kit" {
		return fmt.Errorf("kit kind must be Kit, got %q", k.Kind)
	}
	if strings.TrimSpace(k.Metadata.Name) == "" || len(k.Metadata.Name) > 63 {
		return errors.New("kit metadata.name is required (maximum 63 characters)")
	}
	if k.Spec.Agent == "" && k.Spec.Image == "" {
		return errors.New("kit spec.agent or spec.image is required")
	}
	switch k.Spec.PolicyProfile {
	case "", "deny-all", "balanced", "sbx-compat":
	default:
		return errors.New("kit spec.policy_profile must be deny-all, balanced or sbx-compat")
	}
	if k.Spec.Workspace.Seed != "" {
		if err := validateSeed(k.Spec.Workspace.Seed); err != nil {
			return err
		}
	}
	if len(k.Spec.MCP.Allow) != 0 {
		return errors.New("kit mcp.allow is not implemented by the local runtime")
	}
	for _, mount := range k.Spec.Mounts {
		if mount.Path == "" || !strings.HasPrefix(mount.Path, "/") {
			return errors.New("kit mount paths must be absolute")
		}
	}
	return validateCredentials(k.Spec.Credentials)
}

func validateCredentials(credentials []Credential) error {
	seenCredentials := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		if err := validateCredential(credential, seenCredentials); err != nil {
			return err
		}
	}
	return nil
}

func validateCredential(credential Credential, seenCredentials map[string]struct{}) error {
	if !validServiceName(credential.Service) || credential.OAuth == nil {
		return errors.New("kit credentials require a service and OAuth configuration")
	}
	if _, exists := seenCredentials[credential.Service]; exists {
		return fmt.Errorf("kit credential service %q is duplicated", credential.Service)
	}
	seenCredentials[credential.Service] = struct{}{}
	oauth := credential.OAuth
	if credential.Service == "openai" {
		return validateFixedOpenAIOAuth(oauth)
	}
	return validateOAuthCredential(credential.Service, oauth)
}

func validateFixedOpenAIOAuth(oauth *OAuthCredential) error {
	if len(oauth.ResourceHosts) != 0 && (len(oauth.ResourceHosts) != 1 || oauth.ResourceHosts[0] != "api.openai.com") {
		return errors.New("openai OAuth resourceHosts must contain only api.openai.com")
	}
	if oauth.TokenEndpoint != nil || oauth.Sentinels != nil || oauth.CredentialFile != nil ||
		oauth.ResponseFields != nil || oauth.Passthrough {
		return errors.New("openai OAuth kit uses a fixed daemon-managed provider; custom broker fields are unsupported")
	}
	return nil
}

func validateOAuthCredential(service string, oauth *OAuthCredential) error {
	if oauth.TokenEndpoint == nil || !validOAuthHost(oauth.TokenEndpoint.Host) || !strings.HasPrefix(oauth.TokenEndpoint.Path, "/") || pathpkg.Clean(oauth.TokenEndpoint.Path) != oauth.TokenEndpoint.Path || strings.ContainsAny(oauth.TokenEndpoint.Path, "?#\r\n") {
		return fmt.Errorf("kit OAuth credential %q requires a valid tokenEndpoint", service)
	}
	if !oauth.Passthrough && (oauth.Sentinels == nil || oauth.Sentinels.AccessToken == "" || oauth.Sentinels.RefreshToken == "" || oauth.Sentinels.AccessToken == oauth.Sentinels.RefreshToken) {
		return fmt.Errorf("kit OAuth credential %q requires distinct sentinels unless passthrough is enabled", service)
	}
	if err := validateOAuthHosts(service, oauth); err != nil {
		return err
	}
	if oauth.CredentialFile == nil {
		return nil
	}
	return validateCredentialFile(service, *oauth.CredentialFile)
}

func validateOAuthHosts(service string, oauth *OAuthCredential) error {
	seenHosts := map[string]struct{}{}
	hosts := append([]string(nil), oauth.ResourceHosts...)
	if oauth.TokenEndpoint != nil {
		hosts = append(hosts, oauth.TokenEndpoint.Host)
	}
	for _, host := range hosts {
		if !validOAuthHost(host) {
			return fmt.Errorf("kit OAuth credential %q contains an invalid host", service)
		}
		if _, ok := seenHosts[strings.ToLower(host)]; ok {
			return fmt.Errorf("kit OAuth credential %q contains duplicate hosts", service)
		}
		seenHosts[strings.ToLower(host)] = struct{}{}
	}
	return nil
}

func validateCredentialFile(service string, file CredentialFile) error {
	if (file.Path == "") != (file.Template == "" && len(file.Structure) == 0) {
		return fmt.Errorf("kit OAuth credential %q credentialFile requires path and structure or template", service)
	}
	if file.Path != "" && !validCredentialPath(file.Path) {
		return fmt.Errorf("kit OAuth credential %q credentialFile path must be absolute or start with ~/ and be traversal-free", service)
	}
	return nil
}

func validCredentialPath(value string) bool {
	if strings.HasPrefix(value, "~/") {
		value = "/home/kit/" + strings.TrimPrefix(value, "~/")
	}
	return strings.HasPrefix(value, "/") && pathpkg.Clean(value) == value && !strings.Contains(value, "\\")
}

func validHostRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-'
}

func validServiceName(service string) bool {
	if service == "" || len(service) > 64 {
		return false
	}
	for i, r := range service {
		if !validHostRune(r) && r != '_' {
			return false
		}
		if i == 0 && !validServiceInitialRune(r) {
			return false
		}
	}
	return true
}

func validServiceInitialRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func validOAuthHost(host string) bool {
	// Match Docker kit schema acceptance here. Runtime authorization applies a
	// stricter DNS/TLS policy before a route can be activated.
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@?#\\\r\n\x00 ") {
		return false
	}
	for _, r := range host {
		if !validHostRune(r) {
			return false
		}
	}
	return true
}

// OAuthEnvironment returns proxy references for the supported OAuth entries.
func (k Kit) OAuthEnvironment() []string {
	env := make([]string, 0, len(k.Spec.Credentials))
	for _, credential := range k.Spec.Credentials {
		if credential.OAuth != nil {
			key := ""
			if credential.Service == "openai" {
				key = "OPENAI_API_KEY"
			}
			if key != "" {
				env = append(env, key+"=${oauth:"+credential.Service+"}")
			}
		}
	}
	return env
}

func validateSeed(seed string) error {
	if seed == "" || len(seed) > 2048 || strings.ContainsAny(seed, "\x00\r\n \t") || strings.HasPrefix(seed, "-") {
		return errors.New("kit workspace.seed must be a single git URL")
	}
	if strings.HasPrefix(seed, "https://") || strings.HasPrefix(seed, "ssh://") {
		return nil
	}
	if strings.HasPrefix(seed, "git@") && strings.Contains(seed, ":") {
		return nil
	}
	return errors.New("kit workspace.seed must use https://, ssh:// or git@host:path")
}

// Paths returns mount paths with the conventional :ro suffix.
func (k Kit) Paths() []string {
	out := make([]string, 0, len(k.Spec.Mounts))
	for _, mount := range k.Spec.Mounts {
		path := mount.Path
		if mount.ReadOnly {
			path += ":ro"
		}
		out = append(out, path)
	}
	return out
}
