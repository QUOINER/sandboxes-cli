// Docker Sandboxes kit v3 descriptor parsing (static offline subset).
//
// The grammar is the public docker/sandbox-kit-spec SPEC-v3. Rheic only
// reads descriptors: strict decoding and validation for offline inspection.
// Building or running a v3 kit needs a kit builder and runtime capability
// support, which are not implemented, so loaded descriptors never turn into
// grants or content.
package kit

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// v3SyntaxPrefix dispatches a descriptor to the kit v3 frontend.
const v3SyntaxPrefix = "# syntax="

const (
	v3KindWorkload = "workload"
	v3KindMixin    = "mixin"
	v3KindSet      = "set"
	// v3KindSandbox is the pre-rename spelling of workload, accepted on read.
	v3KindSandbox = "sandbox"
)

// V3Descriptor is the docker/sandbox-kit-spec schemaVersion "3" descriptor.
type V3Descriptor struct {
	SchemaVersion string           `yaml:"schemaVersion" json:"schemaVersion"`
	Kind          string           `yaml:"kind" json:"kind"`
	DisplayName   string           `yaml:"displayName,omitempty" json:"displayName,omitempty"`
	Author        string           `yaml:"author,omitempty" json:"author,omitempty"`
	Description   string           `yaml:"description,omitempty" json:"description,omitempty"`
	SourceURL     string           `yaml:"sourceUrl,omitempty" json:"sourceUrl,omitempty"`
	IconURL       string           `yaml:"iconUrl,omitempty" json:"iconUrl,omitempty"`
	Version       string           `yaml:"version,omitempty" json:"version,omitempty"`
	Licenses      []string         `yaml:"licenses,omitempty" json:"licenses,omitempty"`
	Provides      []string         `yaml:"provides,omitempty" json:"provides,omitempty"`
	Requires      []string         `yaml:"requires,omitempty" json:"requires,omitempty"`
	Integrates    []string         `yaml:"integrates,omitempty" json:"integrates,omitempty"`
	Conflicts     []string         `yaml:"conflicts,omitempty" json:"conflicts,omitempty"`
	Capabilities  []V3Capability   `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Args          map[string]V3Arg `yaml:"args,omitempty" json:"args,omitempty"`
	Build         string           `yaml:"build,omitempty" json:"build,omitempty"`
	Dockerfile    string           `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	Kits          []V3SetKit       `yaml:"kits,omitempty" json:"kits,omitempty"`
	NeedsBuild    bool             `yaml:"-" json:"-"`
}

// V3Capability is one typed, versioned capability request or a group.
type V3Capability struct {
	Type              string         `yaml:"type,omitempty" json:"type,omitempty"`
	Name              string         `yaml:"name,omitempty" json:"name,omitempty"`
	Optional          bool           `yaml:"optional,omitempty" json:"optional,omitempty"`
	Description       string         `yaml:"description,omitempty" json:"description,omitempty"`
	Config            map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
	Source            *V3Source      `yaml:"source,omitempty" json:"source,omitempty"`
	DeclarationBlocks []string       `yaml:"declarationBlocks,omitempty" json:"declarationBlocks,omitempty"`
	Group             *V3Group       `yaml:"group,omitempty" json:"group,omitempty"`
}

// V3Source is diagnostic provenance, never a trust input.
type V3Source struct {
	Kit  string `yaml:"kit,omitempty" json:"kit,omitempty"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// V3Group couples one feature's requests without adding a capability type.
type V3Group struct {
	Name         string         `yaml:"name,omitempty" json:"name,omitempty"`
	Description  string         `yaml:"description,omitempty" json:"description,omitempty"`
	Capabilities []V3Capability `yaml:"capabilities" json:"capabilities"`
}

// V3Arg is one installer-supplied kit argument declaration.
type V3Arg struct {
	Default     string   `yaml:"default,omitempty" json:"default,omitempty"`
	Required    bool     `yaml:"required,omitempty" json:"required,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Enum        []string `yaml:"enum,omitempty" json:"enum,omitempty"`
	Pattern     string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Env         string   `yaml:"env,omitempty" json:"env,omitempty"`
	BuildArg    string   `yaml:"buildArg,omitempty" json:"buildArg,omitempty"`
	BuildSecret string   `yaml:"buildSecret,omitempty" json:"buildSecret,omitempty"`
	HasDefault  bool     `yaml:"-" json:"-"`
}

// UnmarshalYAML records whether default was present so default:"" stays real.
func (a *V3Arg) UnmarshalYAML(node *yaml.Node) error {
	type plain V3Arg
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*a = V3Arg(decoded)
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "default" {
			a.HasDefault = true
		}
	}
	return nil
}

// V3SetKit names one published Kit inside a kind: set descriptor.
type V3SetKit struct {
	Ref    string            `yaml:"ref" json:"ref"`
	Digest string            `yaml:"digest,omitempty" json:"digest,omitempty"`
	Args   map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
}

var (
	v3ArgKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	v3VersionPattern = regexp.MustCompile(`^\d+(\.[0-9A-Za-z-]+)*$`)
	v3ArgRefPattern  = regexp.MustCompile(`\$\{\{\s*kit\.args\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
)

// v3SingletonTypes are policy-shaped capability types with at most one
// entry per declaration block.
var v3SingletonTypes = map[string]struct{}{
	"com.docker.sandbox/network-policy@1":             {},
	"com.docker.sandbox/network-policy@2":             {},
	"com.docker.sandbox/resources@1":                  {},
	"com.docker.sandbox/privileged@1":                 {},
	"com.docker.sandbox/dockerd@1":                    {},
	"com.docker.sandbox/kit-registry@1":               {},
	"com.docker.sandbox/agent-sessions@1":             {},
	"com.docker.sandbox/agent-interactive-sessions@1": {},
	"com.docker.sandbox/lifecycle@1":                  {},
	"com.docker.sandbox/sbx@1":                        {},
	"com.docker.sandbox/long-running@1":               {},
	"com.docker.sandbox/git-identity@1":               {},
}

// isV3Data reports whether the document dispatches to the kit v3 grammar.
func isV3Data(data []byte) bool {
	var header struct {
		SchemaVersion string `yaml:"schemaVersion"`
	}
	if err := yaml.Unmarshal(data, &header); err == nil && header.SchemaVersion == "3" {
		return true
	}
	first, _, _ := bytes.Cut(data, []byte("\n"))
	return bytes.HasPrefix(first, []byte(v3SyntaxPrefix)) && bytes.Contains(first, []byte("sandbox-kit:3"))
}

func decodeV3(data []byte) (Kit, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return Kit{}, errors.New("kit v3 descriptor contains a NUL byte")
	}
	var doc V3Descriptor
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return Kit{}, fmt.Errorf("parse kit v3 descriptor: %w", err)
	}
	if err := validateV3(&doc, data); err != nil {
		return Kit{}, err
	}
	if doc.Kind == v3KindSandbox {
		doc.Kind = v3KindWorkload
	}
	return Kit{V3: &doc}, nil
}

func validateV3(doc *V3Descriptor, data []byte) error {
	if doc.SchemaVersion != "3" {
		return fmt.Errorf("kit v3 descriptor requires schemaVersion %q, got %q", "3", doc.SchemaVersion)
	}
	switch doc.Kind {
	case v3KindWorkload, v3KindMixin, v3KindSandbox, v3KindSet:
	default:
		return fmt.Errorf("kit v3 kind must be workload, mixin or set, got %q", doc.Kind)
	}
	if doc.IconURL != "" && !strings.HasPrefix(doc.IconURL, "https://") {
		return errors.New("kit v3 iconUrl must be an absolute https URL")
	}
	if doc.Version != "" && !v3VersionPattern.MatchString(doc.Version) {
		return fmt.Errorf("kit v3 version %q is not version-shaped", doc.Version)
	}
	if err := validateV3Recipe(doc); err != nil {
		return err
	}
	if err := validateV3Relation(doc.Provides, true, false, "provides"); err != nil {
		return err
	}
	if err := validateV3Relation(doc.Requires, false, true, "requires"); err != nil {
		return err
	}
	if err := validateV3Relation(doc.Integrates, false, true, "integrates"); err != nil {
		return err
	}
	if err := validateV3Relation(doc.Conflicts, false, false, "conflicts"); err != nil {
		return err
	}
	if err := validateV3Capabilities(doc.Capabilities); err != nil {
		return err
	}
	if err := validateV3Args(doc.Args); err != nil {
		return err
	}
	return validateV3ArgReferences(doc, data)
}

// validateV3Recipe enforces the authoring-form exclusivity and set rules.
func validateV3Recipe(doc *V3Descriptor) error {
	recipes := 0
	for _, present := range []bool{doc.Build != "", doc.Dockerfile != "", len(doc.Kits) != 0} {
		if present {
			recipes++
		}
	}
	if recipes > 1 {
		return errors.New("kit v3 build, dockerfile and kits are mutually exclusive")
	}
	if doc.Dockerfile != "" {
		cleaned := path.Clean(doc.Dockerfile)
		if cleaned != doc.Dockerfile || strings.HasPrefix(doc.Dockerfile, "/") || doc.Dockerfile == ".." || strings.HasPrefix(doc.Dockerfile, "../") {
			return errors.New("kit v3 dockerfile must stay inside the descriptor directory")
		}
	}
	if doc.Kind != v3KindSet {
		return nil
	}
	if len(doc.Kits) == 0 {
		return errors.New("kit v3 kind set must list at least one kit")
	}
	for _, entry := range doc.Kits {
		if err := validateV3SetKit(entry); err != nil {
			return err
		}
	}
	return nil
}

func validateV3SetKit(entry V3SetKit) error {
	if entry.Ref == "" || strings.HasPrefix(entry.Ref, ".") || strings.HasPrefix(entry.Ref, "/") || strings.HasPrefix(entry.Ref, "~") || strings.Contains(entry.Ref, "://") || strings.ContainsAny(entry.Ref, "\r\n\t ") {
		return fmt.Errorf("kit v3 set ref %q must be a published registry reference", entry.Ref)
	}
	if entry.Digest != "" {
		rest, ok := strings.CutPrefix(entry.Digest, "sha256:")
		if !ok || len(rest) != 64 || !isHex(rest) {
			return fmt.Errorf("kit v3 set digest %q must be sha256:<64 hex>", entry.Digest)
		}
	}
	return nil
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// validateV3Relation checks provides/requires/integrates/conflicts entries.
// bareVersion allows name@version; constraints allows name <op> ver[, ...].
func validateV3Relation(entries []string, bareVersion, constraints bool, field string) error {
	for _, entry := range entries {
		if err := validateV3RelationEntry(entry, bareVersion, constraints, field); err != nil {
			return err
		}
	}
	return nil
}

func validateV3RelationEntry(entry string, bareVersion, constraints bool, field string) error {
	if strings.Contains(entry, "${{") {
		// Arg references are permitted in provides (and version) only, where
		// they expand at publish; constraint fields must stay literal.
		if !bareVersion {
			return fmt.Errorf("kit v3 %s entries must be literal, found a reference in %q", field, entry)
		}
		return validateV3CapabilityName(strings.SplitN(entry, "@", 2)[0], field)
	}
	name, version, found := strings.Cut(entry, "@")
	if found {
		if !bareVersion || !v3VersionPattern.MatchString(version) {
			return fmt.Errorf("kit v3 %s entry %q is not name@version", field, entry)
		}
		return validateV3CapabilityName(name, field)
	}
	if !constraints {
		if strings.ContainsAny(entry, ",<>= ") {
			return fmt.Errorf("kit v3 %s entry %q must be a bare name", field, entry)
		}
		return validateV3CapabilityName(entry, field)
	}
	parts := strings.Split(entry, ",")
	name, first, constrained := strings.Cut(strings.TrimSpace(parts[0]), " ")
	if err := validateV3CapabilityName(strings.TrimSpace(name), field); err != nil {
		return err
	}
	if !constrained {
		if len(parts) > 1 {
			return fmt.Errorf("kit v3 %s entry %q constrains an unconstrained name", field, entry)
		}
		return nil
	}
	segments := append([]string{strings.TrimSpace(first)}, trimmedParts(parts[1:])...)
	for _, segment := range segments {
		_, ok := cutConstraintOp(segment)
		if !ok {
			return fmt.Errorf("kit v3 %s entry %q has an invalid constraint %q", field, entry, segment)
		}
	}
	return nil
}

func trimmedParts(parts []string) []string {
	trimmed := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed = append(trimmed, strings.TrimSpace(part))
	}
	return trimmed
}

func cutConstraintOp(segment string) (string, bool) {
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(segment, op); ok {
			version := strings.TrimSpace(rest)
			return version, v3VersionPattern.MatchString(version)
		}
	}
	return "", false
}

// validateV3CapabilityName checks the §5.1 name and namespace grammar.
func validateV3CapabilityName(name, field string) error {
	if name == "" {
		return fmt.Errorf("kit v3 %s entry has an empty name", field)
	}
	namespace, base, found := strings.Cut(name, "/")
	if found {
		if namespace == "deb" || namespace == "apk" {
			return fmt.Errorf("kit v3 %s entry %q uses a namespace reserved for derived provides", field, name)
		}
		if err := validateV3Namespace(namespace); err != nil {
			return fmt.Errorf("kit v3 %s entry %q has an invalid namespace", field, name)
		}
	} else {
		base = namespace
	}
	if !validV3BaseName(base) {
		return fmt.Errorf("kit v3 %s entry %q has an invalid name", field, name)
	}
	return nil
}

func validateV3Namespace(namespace string) error {
	if len(namespace) > 253 {
		return errors.New("namespace exceeds 253 characters")
	}
	for _, label := range strings.Split(namespace, ".") {
		if label == "" || len(label) > 63 || !isDNSLabel(label) {
			return fmt.Errorf("namespace label %q is invalid", label)
		}
	}
	return nil
}

func isDNSLabel(label string) bool {
	for i, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && (r < 'A' || r > 'Z') {
			return false
		}
		if (i == 0 || i == len(label)-1) && r == '-' {
			return false
		}
	}
	return true
}

func validV3BaseName(base string) bool {
	if base == "" {
		return false
	}
	for i, r := range base {
		switch {
		case 'a' <= r && r <= 'z' || '0' <= r && r <= '9':
		case r == '-' || r == '.' || r == '+' || r == '_':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	last := base[len(base)-1]
	return last != '-' && last != '.'
}

// validateV3Capabilities checks entry grammar, duplicates and singleton arity.
func validateV3Capabilities(entries []V3Capability) error {
	seen := map[string]struct{}{}
	singletons := map[string]struct{}{}
	for _, entry := range entries {
		if err := validateV3Capability(entry, seen, singletons, true); err != nil {
			return err
		}
	}
	_, hasV1 := singletons["com.docker.sandbox/network-policy@1"]
	_, hasV2 := singletons["com.docker.sandbox/network-policy@2"]
	if hasV1 && hasV2 {
		return errors.New("kit v3 network-policy@1 and network-policy@2 are mutually exclusive")
	}
	return nil
}

func validateV3Capability(entry V3Capability, seen, singletons map[string]struct{}, topLevel bool) error {
	if entry.Group != nil {
		if entry.Type != "" || entry.Config != nil || !topLevel {
			return errors.New("kit v3 capability group cannot mix with a type or nest")
		}
		return validateV3Group(entry.Group, seen, singletons)
	}
	if err := validateV3CapabilityType(entry.Type); err != nil {
		return err
	}
	if !topLevel && len(entry.DeclarationBlocks) != 0 {
		return errors.New("kit v3 declarationBlocks is not permitted on group members")
	}
	key := entry.Type
	if _, exists := seen[key]; exists {
		return fmt.Errorf("kit v3 capability %q is duplicated", entry.Type)
	}
	seen[key] = struct{}{}
	if _, singleton := v3SingletonTypes[entry.Type]; singleton {
		if _, exists := singletons[entry.Type]; exists {
			return fmt.Errorf("kit v3 capability %q allows at most one entry", entry.Type)
		}
		singletons[entry.Type] = struct{}{}
	}
	return nil
}

func validateV3Group(group *V3Group, seen, singletons map[string]struct{}) error {
	if len(group.Capabilities) == 0 {
		return errors.New("kit v3 capability group must contain at least one request")
	}
	for _, member := range group.Capabilities {
		if err := validateV3Capability(member, seen, singletons, false); err != nil {
			return err
		}
	}
	return nil
}

// validateV3CapabilityType checks the <namespace>/<name>@<version> grammar.
func validateV3CapabilityType(typeName string) error {
	namespace, rest, found := strings.Cut(typeName, "/")
	if !found {
		return fmt.Errorf("kit v3 capability type %q must be <namespace>/<name>@<version>", typeName)
	}
	if err := validateV3Namespace(namespace); err != nil {
		return fmt.Errorf("kit v3 capability type %q has an invalid namespace", typeName)
	}
	name, version, found := strings.Cut(rest, "@")
	if !found || version == "" {
		return fmt.Errorf("kit v3 capability type %q must name a version", typeName)
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return fmt.Errorf("kit v3 capability type %q has a non-integer version", typeName)
		}
	}
	if !validV3TypeName(name) {
		return fmt.Errorf("kit v3 capability type %q has an invalid name", typeName)
	}
	return nil
}

func validV3TypeName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case 'a' <= r && r <= 'z' || '0' <= r && r <= '9':
		case r == '-':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validateV3Args checks argument declarations: keys, delivery mutex and value
// constraint shapes. Runtime expansion stays with the unimplemented builder.
func validateV3Args(args map[string]V3Arg) error {
	names := make(map[string]struct{}, len(args))
	for key := range args {
		if !v3ArgKeyPattern.MatchString(key) {
			return fmt.Errorf("kit v3 arg name %q is invalid", key)
		}
		names[key] = struct{}{}
		if err := validateV3Arg(key, args[key]); err != nil {
			return err
		}
	}
	return nil
}

func validateV3Arg(key string, arg V3Arg) error {
	if arg.HasDefault && arg.Required {
		return fmt.Errorf("kit v3 arg %q cannot set default and required together", key)
	}
	if len(arg.Enum) != 0 && arg.Pattern != "" {
		return fmt.Errorf("kit v3 arg %q cannot set enum and pattern together", key)
	}
	delivery := 0
	for _, value := range []string{arg.Env, arg.BuildArg, arg.BuildSecret} {
		if value != "" {
			delivery++
		}
	}
	if delivery > 1 {
		return fmt.Errorf("kit v3 arg %q must choose at most one of env, buildArg and buildSecret", key)
	}
	if arg.Pattern != "" {
		if _, err := regexp.Compile(arg.Pattern); err != nil {
			return fmt.Errorf("kit v3 arg %q pattern is invalid: %w", key, err)
		}
	}
	for _, value := range arg.Enum {
		if value == "" {
			return fmt.Errorf("kit v3 arg %q enum contains an empty value", key)
		}
	}
	return nil
}

// validateV3ArgReferences enforces that every ${{ kit.args.X }} reference in
// the document names a declared arg, and that build-secret args stay
// unreferenced.
func validateV3ArgReferences(doc *V3Descriptor, data []byte) error {
	for _, match := range v3ArgRefPattern.FindAllSubmatch(data, -1) {
		name := string(match[1])
		arg, declared := doc.Args[name]
		if !declared {
			return fmt.Errorf("kit v3 references undeclared arg %q", name)
		}
		if arg.BuildSecret != "" {
			return fmt.Errorf("kit v3 arg %q is a build secret and cannot be referenced", name)
		}
	}
	return nil
}
