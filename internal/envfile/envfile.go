// Package envfile loads the deliberately limited, read-only subset of
// Docker Sandboxes environment files currently supported by Rheic.
package envfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxFileSize  = 1 << 20
	maxYAMLNodes = 20_000
	maxYAMLDepth = 64
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Workspace is a host directory the preview would mount.
type Workspace struct {
	Path     string
	ReadOnly bool
}

// Plan contains only non-secret information safe to display in a static
// preview. Environment values are intentionally discarded after key names
// have been collected.
type Plan struct {
	Name                 string
	Agent                string
	Workspace            string
	AdditionalWorkspaces []Workspace
	EnvironmentKeys      []string
	CPUs                 *uint32
	Memory               string
}

type document struct {
	SchemaVersion        string            `yaml:"schemaVersion"`
	Name                 string            `yaml:"name"`
	Agent                string            `yaml:"agent"`
	Workspace            workspaceValue    `yaml:"workspace"`
	AdditionalWorkspaces []workspaceMount  `yaml:"additionalWorkspaces"`
	Env                  map[string]string `yaml:"env"`
	SandboxOptions       sandboxOptions    `yaml:"sandboxOptions"`
}

type workspaceValue struct {
	Path string
}

func (w *workspaceValue) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		w.Path = node.Value
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("invalid workspace")
	}
	var path string
	seenPath := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, field := node.Content[i].Value, node.Content[i+1]
		if key != "path" {
			return errors.New("unsupported workspace field")
		}
		if seenPath {
			return errors.New("duplicate workspace path")
		}
		seenPath = true
		if field.Kind != yaml.ScalarNode || field.Tag != "!!str" {
			return errors.New("invalid workspace path")
		}
		path = field.Value
	}
	w.Path = path
	return nil
}

type workspaceMount struct {
	Path     string `yaml:"path"`
	ReadOnly bool   `yaml:"readOnly"`
}

type sandboxOptions struct {
	CPUs   *uint32 `yaml:"cpus"`
	Memory string  `yaml:"memory"`
}

// Load resolves one or more explicit files. A directory means
// <directory>/sbxenv.yaml. Files are validated before they are merged.
func Load(paths []string) (Plan, error) {
	if len(paths) == 0 {
		return Plan{}, errors.New("an explicit environment file or directory is required")
	}
	var plan Plan
	for _, path := range paths {
		filePath, err := resolveFile(path)
		if err != nil {
			return Plan{}, err
		}
		doc, err := readDocument(filePath)
		if err != nil {
			return Plan{}, err
		}
		if err := doc.validate(); err != nil {
			return Plan{}, err
		}
		plan, err = mergeDocument(plan, doc, filePath)
		if err != nil {
			return Plan{}, err
		}
	}
	if plan.Agent == "" {
		return Plan{}, errors.New("environment requires an agent")
	}
	sort.Strings(plan.EnvironmentKeys)
	return plan, nil
}

func mergeDocument(plan Plan, doc document, filePath string) (Plan, error) {
	if doc.Name != "" {
		plan.Name = doc.Name
	}
	if doc.Agent != "" {
		plan.Agent = doc.Agent
	}
	if doc.Workspace.Path != "" {
		resolved, err := resolveWorkspace(filePath, doc.Workspace.Path)
		if err != nil {
			return Plan{}, err
		}
		plan.Workspace = resolved
	}
	for _, mount := range doc.AdditionalWorkspaces {
		resolved, err := resolveWorkspace(filePath, mount.Path)
		if err != nil {
			return Plan{}, err
		}
		plan.AdditionalWorkspaces = append(plan.AdditionalWorkspaces, Workspace{Path: resolved, ReadOnly: mount.ReadOnly})
	}
	plan.EnvironmentKeys = mergeEnvironmentKeys(plan.EnvironmentKeys, doc.Env)
	if doc.SandboxOptions.CPUs != nil {
		value := *doc.SandboxOptions.CPUs
		plan.CPUs = &value
	}
	if doc.SandboxOptions.Memory != "" {
		plan.Memory = doc.SandboxOptions.Memory
	}
	return plan, nil
}

func mergeEnvironmentKeys(existing []string, env map[string]string) []string {
	keys := make(map[string]struct{}, len(existing)+len(env))
	for _, key := range existing {
		keys[key] = struct{}{}
	}
	for key := range env {
		keys[key] = struct{}{}
	}
	merged := make([]string, 0, len(keys))
	for key := range keys {
		merged = append(merged, key)
	}
	return merged
}

func (d document) validate() error {
	if d.SchemaVersion != "1" {
		return errors.New("environment schemaVersion must be \"1\"")
	}
	if err := validateIdentifiers(d); err != nil {
		return err
	}
	if err := validateWorkspaces(d); err != nil {
		return err
	}
	if err := validateEnvironment(d.Env); err != nil {
		return err
	}
	return validateOptions(d.SandboxOptions)
}

func validateIdentifiers(d document) error {
	if d.Name != "" && !identifier.MatchString(d.Name) {
		return errors.New("environment name is invalid")
	}
	if d.Agent != "" && !identifier.MatchString(d.Agent) {
		return errors.New("environment agent is invalid")
	}
	return nil
}

func validateWorkspaces(d document) error {
	if d.Workspace.Path != "" && strings.TrimSpace(d.Workspace.Path) == "" {
		return errors.New("environment workspace path is invalid")
	}
	for _, mount := range d.AdditionalWorkspaces {
		if strings.TrimSpace(mount.Path) == "" {
			return errors.New("additional workspace path is required")
		}
	}
	return nil
}

func validateEnvironment(env map[string]string) error {
	for key := range env {
		if !validEnvironmentKey(key) {
			return errors.New("environment contains an invalid variable name")
		}
	}
	return nil
}

func validateOptions(options sandboxOptions) error {
	if options.CPUs != nil && (*options.CPUs == 0 || *options.CPUs > 256) {
		return errors.New("environment CPU count is out of range")
	}
	if options.Memory != "" && !validMemorySize(options.Memory) {
		return errors.New("environment memory size is invalid")
	}
	return nil
}

func validEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func validMemorySize(value string) bool {
	if len(value) < 2 {
		return false
	}
	suffix := strings.ToLower(value[len(value)-1:])
	amount, err := strconv.ParseUint(value[:len(value)-1], 10, 32)
	if err != nil {
		return false
	}
	switch suffix {
	case "m":
		return amount >= 512 && amount <= 1<<20
	case "g":
		return amount >= 1 && amount <= 1<<10
	default:
		return false
	}
}

func resolveFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("environment path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve environment path")
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", errors.New("inspect environment path")
	}
	if info.IsDir() {
		absolute = filepath.Join(absolute, "sbxenv.yaml")
	}
	return absolute, nil
}

func readDocument(path string) (document, error) {
	file, err := os.Open(path) // #nosec G304 -- path is an explicit user-selected environment file
	if err != nil {
		return document{}, errors.New("open environment file")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil || len(data) > maxFileSize {
		return document{}, errors.New("read environment file")
	}
	return decodeDocument(data)
}

func decodeDocument(data []byte) (document, error) {
	if len(data) > maxFileSize {
		return document{}, errors.New("read environment file")
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return document{}, errors.New("environment file has invalid YAML or unsupported fields")
	}
	if err := validateYAMLTree(&root); err != nil {
		return document{}, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return document{}, errors.New("environment file must contain exactly one YAML document")
	}
	decoder = yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return document{}, errors.New("environment file has invalid YAML or unsupported fields")
	}
	return doc, nil
}

func validateYAMLTree(root *yaml.Node) error {
	type pendingNode struct {
		node  *yaml.Node
		depth int
	}
	pending := []pendingNode{{node: root, depth: 1}}
	nodes := 0
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		nodes++
		if nodes > maxYAMLNodes {
			return errors.New("environment file has too many YAML nodes")
		}
		if current.depth > maxYAMLDepth {
			return errors.New("environment file YAML nesting is too deep")
		}
		if current.node.Kind == yaml.AliasNode {
			return errors.New("YAML aliases are unsupported in environment files")
		}
		for _, child := range current.node.Content {
			pending = append(pending, pendingNode{node: child, depth: current.depth + 1})
		}
	}
	return nil
}

func resolveWorkspace(filePath, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	resolved, err := filepath.Abs(filepath.Join(filepath.Dir(filePath), path))
	if err != nil {
		return "", errors.New("resolve workspace path")
	}
	return filepath.Clean(resolved), nil
}
