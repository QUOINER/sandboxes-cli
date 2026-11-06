// Package envfile loads the deliberately limited, read-only subset of
// Docker Sandboxes environment files currently supported by Rheic.
package envfile

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxFileSize   = 1 << 20
	maxYAMLNodes  = 20_000
	maxYAMLDepth  = 64
	yamlStringTag = "!!str"
	argumentKey   = "args"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
var argumentIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
var directoryReference = regexp.MustCompile(`\$\{\{\s*env\.([A-Za-z][A-Za-z0-9]*)\s*\}\}`)
var argumentReference = regexp.MustCompile(`\$\{\{\s*env\.args\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// ValidateName checks a name before the CLI applies a command-line override.
func ValidateName(name string) error {
	if !identifier.MatchString(name) {
		return errors.New("environment name is invalid")
	}
	return nil
}

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
	Ports                []Port
	ArgumentNames        []string
	EnvironmentKeys      []string
	CPUs                 *uint32
	Memory               string
	arguments            map[string]argumentDeclaration
}

// ArgumentOverrides contains values read from argument files followed by
// command-line values. Command-line values take precedence.
type ArgumentOverrides struct {
	Files  []string
	Values []string
}

type document struct {
	SchemaVersion        string                         `yaml:"schemaVersion"`
	Name                 string                         `yaml:"name"`
	Agent                string                         `yaml:"agent"`
	Workspace            workspaceValue                 `yaml:"workspace"`
	AdditionalWorkspaces []workspaceMount               `yaml:"additionalWorkspaces"`
	Ports                []portMapping                  `yaml:"ports"`
	Args                 map[string]argumentDeclaration `yaml:"args"`
	Env                  map[string]string              `yaml:"env"`
	SandboxOptions       sandboxOptions                 `yaml:"sandboxOptions"`
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

// Port is a sandbox port declaration shown in the static environment preview.
type Port struct {
	Sandbox  uint16
	Host     *uint16
	Protocol string
	HostIP   string
}

type portMapping struct {
	Sandbox  *uint16 `yaml:"sandbox"`
	Host     *uint16 `yaml:"host"`
	Protocol string  `yaml:"protocol"`
	HostIP   string  `yaml:"hostIP"`
}

type argumentDeclaration struct {
	Default     *string  `yaml:"default"`
	Required    *bool    `yaml:"required"`
	Description *string  `yaml:"description"`
	Enum        []string `yaml:"enum"`
	Pattern     *string  `yaml:"pattern"`
}

type sandboxOptions struct {
	CPUs   *uint32 `yaml:"cpus"`
	Memory string  `yaml:"memory"`
}

// Load resolves one or more explicit files. A directory means
// <directory>/sbxenv.yaml. Files are validated before they are merged.
func Load(paths []string) (Plan, error) {
	return LoadWithArguments(paths, ArgumentOverrides{})
}

// LoadWithArguments resolves explicit files and applies transient argument
// overrides without retaining or returning any argument values.
func LoadWithArguments(paths []string, overrides ArgumentOverrides) (Plan, error) {
	if len(paths) == 0 {
		return Plan{}, errors.New("an explicit environment file or directory is required")
	}
	firstFile, err := resolveFile(paths[0])
	if err != nil {
		return Plan{}, err
	}
	return load(paths, filepath.Dir(firstFile), overrides)
}

func load(paths []string, projectDir string, overrides ArgumentOverrides) (Plan, error) {
	documents, arguments, err := readSourceDocuments(paths)
	if err != nil {
		return Plan{}, err
	}
	names, argumentValues, err := resolveArgumentValues(arguments, overrides)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{arguments: arguments}
	for _, source := range documents {
		if err := interpolateArgumentReferences(source.node, argumentValues); err != nil {
			return Plan{}, err
		}
		doc, err := decodeDocumentNode(source.node)
		if err != nil {
			return Plan{}, err
		}
		if err := doc.validate(); err != nil {
			return Plan{}, err
		}
		plan, err = mergeDocument(plan, doc, source.path, projectDir)
		if err != nil {
			return Plan{}, err
		}
	}
	if plan.Agent == "" {
		return Plan{}, errors.New("environment requires an agent")
	}
	plan.ArgumentNames = names
	plan.arguments = nil
	sort.Strings(plan.EnvironmentKeys)
	sort.Strings(plan.ArgumentNames)
	return plan, nil
}

type sourceDocument struct {
	path string
	node *yaml.Node
}

func readSourceDocuments(paths []string) ([]sourceDocument, map[string]argumentDeclaration, error) {
	documents := make([]sourceDocument, 0, len(paths))
	var arguments map[string]argumentDeclaration
	for _, path := range paths {
		filePath, err := resolveFile(path)
		if err != nil {
			return nil, nil, err
		}
		root, err := readDocumentNode(filePath)
		if err != nil {
			return nil, nil, err
		}
		declarations, err := decodeArgumentDefinitions(root)
		if err != nil {
			return nil, nil, err
		}
		if err := validateArgumentDefinitions(declarations); err != nil {
			return nil, nil, err
		}
		if err := rejectArgumentReferencesInDefinitions(root); err != nil {
			return nil, nil, err
		}
		if len(declarations) > 0 && arguments == nil {
			arguments = make(map[string]argumentDeclaration)
		}
		for name, declaration := range declarations {
			arguments[name] = declaration
		}
		documents = append(documents, sourceDocument{path: filePath, node: root})
	}
	return documents, arguments, nil
}

// LoadDefault resolves the current-directory environment with optional
// user-level defaults. Explicit paths should use Load so home defaults are
// skipped, matching the sbx env command contract.
func LoadDefault(homeDir, workingDir string) (Plan, error) {
	return LoadDefaultWithArguments(homeDir, workingDir, ArgumentOverrides{})
}

// LoadDefaultWithArguments resolves user defaults and the current-directory
// file, then validates transient argument values.
func LoadDefaultWithArguments(homeDir, workingDir string, overrides ArgumentOverrides) (Plan, error) {
	if strings.TrimSpace(homeDir) == "" || strings.TrimSpace(workingDir) == "" {
		return Plan{}, errors.New("resolve default environment paths")
	}
	paths := make([]string, 0, 2)
	homeFile := filepath.Join(homeDir, ".sbxenv.yaml")
	if info, err := os.Stat(homeFile); err == nil {
		if !info.Mode().IsRegular() {
			return Plan{}, errors.New("user environment defaults are not a regular file")
		}
		paths = append(paths, homeFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Plan{}, errors.New("inspect user environment defaults")
	}
	paths = append(paths, workingDir)
	projectDir, err := filepath.Abs(workingDir)
	if err != nil {
		return Plan{}, errors.New("resolve default environment paths")
	}
	return load(paths, filepath.Clean(projectDir), overrides)
}

func mergeDocument(plan Plan, doc document, filePath, projectDir string) (Plan, error) {
	if doc.Name != "" {
		plan.Name = doc.Name
	}
	if doc.Agent != "" {
		plan.Agent = doc.Agent
	}
	if doc.Workspace.Path != "" {
		resolved, err := resolveWorkspace(filePath, doc.Workspace.Path, projectDir)
		if err != nil {
			return Plan{}, err
		}
		plan.Workspace = resolved
	}
	for _, mount := range doc.AdditionalWorkspaces {
		resolved, err := resolveWorkspace(filePath, mount.Path, projectDir)
		if err != nil {
			return Plan{}, err
		}
		plan.AdditionalWorkspaces = append(plan.AdditionalWorkspaces, Workspace{Path: resolved, ReadOnly: mount.ReadOnly})
	}
	if len(doc.Args) > 0 && plan.arguments == nil {
		plan.arguments = make(map[string]argumentDeclaration, len(doc.Args))
	}
	for name, declaration := range doc.Args {
		plan.arguments[name] = declaration
	}
	for _, port := range doc.Ports {
		var host *uint16
		if port.Host != nil {
			value := *port.Host
			host = &value
		}
		plan.Ports = append(plan.Ports, Port{Sandbox: *port.Sandbox, Host: host, Protocol: port.Protocol, HostIP: port.HostIP})
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
	if err := validatePorts(d.Ports); err != nil {
		return err
	}
	if err := validateArgumentDefinitions(d.Args); err != nil {
		return err
	}
	return validateOptions(d.SandboxOptions)
}

func validateArgumentDefinitions(arguments map[string]argumentDeclaration) error {
	for name, declaration := range arguments {
		if err := validateArgumentDefinition(name, declaration); err != nil {
			return err
		}
	}
	return nil
}

func validateArgumentDefinition(name string, declaration argumentDeclaration) error {
	if !argumentIdentifier.MatchString(name) {
		return errors.New("environment argument name is invalid")
	}
	hasDefault := declaration.Default != nil
	required := declaration.Required != nil && *declaration.Required
	if hasDefault == required || declaration.Required != nil && !*declaration.Required && !hasDefault {
		return errors.New("environment argument must set exactly one of default or required: true")
	}
	if declaration.Enum != nil && declaration.Pattern != nil {
		return errors.New("environment argument cannot set both enum and pattern")
	}
	if declaration.Pattern != nil {
		if _, err := regexp.Compile(*declaration.Pattern); err != nil {
			return errors.New("environment argument pattern is invalid")
		}
	}
	if declaration.Default != nil {
		return validateArgumentValue(*declaration.Default, declaration)
	}
	return nil
}

func resolveArgumentValues(arguments map[string]argumentDeclaration, overrides ArgumentOverrides) ([]string, map[string]string, error) {
	provided := make(map[string]string)
	for _, path := range overrides.Files {
		values, err := readArgumentFile(path)
		if err != nil {
			return nil, nil, err
		}
		for name, value := range values {
			provided[name] = value
		}
	}
	cliValues := make(map[string]string)
	if err := parseArgumentValues(overrides.Values, cliValues); err != nil {
		return nil, nil, err
	}
	for name, value := range cliValues {
		provided[name] = value
	}
	for name := range provided {
		if _, ok := arguments[name]; !ok {
			return nil, nil, errors.New("value supplied for an undeclared environment argument")
		}
	}
	values := make(map[string]string, len(arguments))
	names := make([]string, 0, len(arguments))
	for name, declaration := range arguments {
		value, hasValue := provided[name]
		if !hasValue && declaration.Default != nil {
			value = *declaration.Default
			hasValue = true
		}
		if !hasValue {
			return nil, nil, errors.New("required environment argument is missing")
		}
		if err := validateArgumentValue(value, declaration); err != nil {
			return nil, nil, err
		}
		values[name] = value
		names = append(names, name)
	}
	sort.Strings(names)
	return names, values, nil
}

func decodeArgumentDefinitions(root *yaml.Node) (map[string]argumentDeclaration, error) {
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("environment file must be a YAML mapping")
	}
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		key, value := root.Content[0].Content[i], root.Content[0].Content[i+1]
		if key.Value != argumentKey {
			continue
		}
		var args map[string]argumentDeclaration
		if err := value.Decode(&args); err != nil {
			return nil, errors.New("environment file has invalid argument declarations")
		}
		return args, nil
	}
	return make(map[string]argumentDeclaration), nil
}

func rejectArgumentReferencesInDefinitions(root *yaml.Node) error {
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("environment file must be a YAML mapping")
	}
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		if root.Content[0].Content[i].Value == argumentKey && nodeContainsArgumentReference(root.Content[0].Content[i+1]) {
			return errors.New("environment arguments cannot reference other arguments")
		}
	}
	return nil
}

func nodeContainsArgumentReference(node *yaml.Node) bool {
	if node.Kind == yaml.ScalarNode && node.Tag == yamlStringTag && argumentReference.FindStringIndex(node.Value) != nil {
		return true
	}
	for _, child := range node.Content {
		if nodeContainsArgumentReference(child) {
			return true
		}
	}
	return false
}

func interpolateArgumentReferences(root *yaml.Node, values map[string]string) error {
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("environment file must be a YAML mapping")
	}
	budget := 0
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		key, value := root.Content[0].Content[i], root.Content[0].Content[i+1]
		if key.Value == argumentKey {
			continue
		}
		if err := interpolateNode(value, values, &budget); err != nil {
			return err
		}
	}
	return nil
}

func interpolateNode(node *yaml.Node, values map[string]string, budget *int) error {
	if node.Kind == yaml.ScalarNode {
		if err := interpolateScalar(node, values); err != nil {
			return err
		}
		*budget += len(node.Value)
		if *budget > maxFileSize {
			return errors.New("expanded environment file exceeds size limit")
		}
		return nil
	}
	if node.Kind == yaml.MappingNode {
		return interpolateMappingNode(node, values, budget)
	}
	for _, child := range node.Content {
		if err := interpolateNode(child, values, budget); err != nil {
			return err
		}
	}
	return nil
}

func interpolateMappingNode(node *yaml.Node, values map[string]string, budget *int) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if nodeContainsArgumentReference(key) {
			return errors.New("environment argument references cannot appear in field names")
		}
		if err := interpolateNode(key, values, budget); err != nil {
			return err
		}
		if err := interpolateNode(value, values, budget); err != nil {
			return err
		}
	}
	return nil
}

func interpolateScalar(node *yaml.Node, values map[string]string) error {
	if node.Kind != yaml.ScalarNode || node.Tag != yamlStringTag {
		return nil
	}
	matches := argumentReference.FindAllStringSubmatchIndex(node.Value, -1)
	if len(matches) == 0 {
		return nil
	}
	resolved, err := replaceArgumentReferences(node.Value, matches, values)
	if err != nil {
		return err
	}
	if len(matches) == 1 && matches[0][0] == 0 && matches[0][1] == len(node.Value) && node.Style == 0 {
		return setPlainScalar(node, resolved)
	}
	node.Value = resolved
	return nil
}

func replaceArgumentReferences(source string, matches [][]int, values map[string]string) (string, error) {
	outputSize := len(source)
	for _, match := range matches {
		if match[0] > 0 && source[match[0]-1] == '$' {
			outputSize--
			continue
		}
		value, ok := values[source[match[2]:match[3]]]
		if !ok {
			return "", errors.New("environment references an undeclared argument")
		}
		outputSize += len(value) - (match[1] - match[0])
		if outputSize > maxFileSize {
			return "", errors.New("expanded environment file exceeds size limit")
		}
	}
	var resolved strings.Builder
	resolved.Grow(outputSize)
	last := 0
	for _, match := range matches {
		if match[0] > 0 && source[match[0]-1] == '$' {
			resolved.WriteString(source[last : match[0]-1])
			resolved.WriteString(source[match[0]:match[1]])
			last = match[1]
			continue
		}
		value, ok := values[source[match[2]:match[3]]]
		if !ok {
			return "", errors.New("environment references an undeclared argument")
		}
		resolved.WriteString(source[last:match[0]])
		resolved.WriteString(value)
		last = match[1]
	}
	resolved.WriteString(source[last:])
	return resolved.String(), nil
}

func setPlainScalar(node *yaml.Node, value string) error {
	var parsed yaml.Node
	if err := yaml.Unmarshal([]byte(value), &parsed); err != nil || parsed.Kind != yaml.DocumentNode || len(parsed.Content) != 1 || parsed.Content[0].Kind != yaml.ScalarNode {
		return errors.New("environment argument must substitute to a YAML scalar")
	}
	scalar := parsed.Content[0]
	node.Tag = scalar.Tag
	node.Value = scalar.Value
	return nil
}

func validateArgumentValue(value string, declaration argumentDeclaration) error {
	if declaration.Enum != nil {
		for _, candidate := range declaration.Enum {
			if value == candidate {
				return nil
			}
		}
		return errors.New("environment argument is not one of its allowed enum values")
	}
	if declaration.Pattern != nil {
		compiled, err := regexp.Compile(*declaration.Pattern)
		if err != nil {
			return errors.New("environment argument pattern is invalid")
		}
		match := compiled.FindStringIndex(value)
		if len(match) != 2 || match[0] != 0 || match[1] != len(value) {
			return errors.New("environment argument does not match its required pattern")
		}
	}
	return nil
}

func parseArgumentValues(values []string, destination map[string]string) error {
	for _, item := range values {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !argumentIdentifier.MatchString(name) {
			return errors.New("environment argument must use name=value syntax")
		}
		destination[name] = value
	}
	return nil
}

func readArgumentFile(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("environment argument file path is required")
	}
	file, err := os.Open(path) // #nosec G304 -- path is an explicit user-selected argument file
	if err != nil {
		return nil, errors.New("open environment argument file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("environment argument file must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil || len(data) > maxFileSize {
		return nil, errors.New("read environment argument file")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if err := parseArgumentValues([]string{line}, values); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func validatePorts(ports []portMapping) error {
	for _, port := range ports {
		if port.Sandbox == nil || *port.Sandbox == 0 {
			return errors.New("environment port requires a sandbox port from 1 through 65535")
		}
		if port.Host != nil && *port.Host == 0 {
			return errors.New("environment host port must be from 1 through 65535")
		}
		switch port.Protocol {
		case "", "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		default:
			return errors.New("environment port protocol is invalid")
		}
		if port.HostIP != "" && net.ParseIP(port.HostIP) == nil {
			return errors.New("environment port hostIP must be an IP address")
		}
	}
	return nil
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

func readDocumentNode(path string) (*yaml.Node, error) {
	file, err := os.Open(path) // #nosec G304 -- path is an explicit user-selected environment file
	if err != nil {
		return nil, errors.New("open environment file")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil || len(data) > maxFileSize {
		return nil, errors.New("read environment file")
	}
	return decodeDocumentNodeFromBytes(data)
}

func decodeDocument(data []byte) (document, error) {
	root, err := decodeDocumentNodeFromBytes(data)
	if err != nil {
		return document{}, err
	}
	return decodeDocumentNode(root)
}

func decodeDocumentNodeFromBytes(data []byte) (*yaml.Node, error) {
	if len(data) > maxFileSize {
		return nil, errors.New("read environment file")
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, errors.New("environment file has invalid YAML or unsupported fields")
	}
	if err := validateYAMLTree(&root); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("environment file must contain exactly one YAML document")
	}
	return &root, nil
}

func decodeDocumentNode(root *yaml.Node) (document, error) {
	var encoded strings.Builder
	encoder := yaml.NewEncoder(&encoded)
	if err := encoder.Encode(root); err != nil {
		return document{}, errors.New("environment file has invalid YAML or unsupported fields")
	}
	if err := encoder.Close(); err != nil {
		return document{}, errors.New("environment file has invalid YAML or unsupported fields")
	}
	decoder := yaml.NewDecoder(strings.NewReader(encoded.String()))
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

func resolveWorkspace(filePath, path, projectDir string) (string, error) {
	path, err := expandDirectoryReferences(path, filepath.Dir(filePath), projectDir)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	resolved, err := filepath.Abs(filepath.Join(filepath.Dir(filePath), path))
	if err != nil {
		return "", errors.New("resolve workspace path")
	}
	return filepath.Clean(resolved), nil
}

func expandDirectoryReferences(value, fileDir, projectDir string) (string, error) {
	unexpanded := directoryReference.ReplaceAllString(value, "")
	if strings.Contains(unexpanded, "${{") {
		return "", errors.New("unsupported environment directory reference")
	}
	var expansionErr error
	expanded := directoryReference.ReplaceAllStringFunc(value, func(reference string) string {
		if expansionErr != nil {
			return reference
		}
		match := directoryReference.FindStringSubmatch(reference)
		if len(match) != 2 {
			expansionErr = errors.New("invalid environment directory reference")
			return reference
		}
		switch match[1] {
		case "projectDir":
			return projectDir
		case "fileDir":
			return fileDir
		default:
			expansionErr = errors.New("unsupported environment directory reference")
			return reference
		}
	})
	if expansionErr != nil {
		return "", expansionErr
	}
	return expanded, nil
}
