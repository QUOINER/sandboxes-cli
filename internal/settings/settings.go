// Package settings reads and writes the host-side Rheic settings file.
package settings

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Setting value types used by the catalog.
const (
	TypeBool   = "bool"
	TypeInt    = "int"
	TypeString = "string"
	TypeJSON   = "json"
)

// Values are the supported user overrides. Docker-matrix keys that the local
// runtime does not consume yet are stored verbatim in Extra so they survive
// round trips and report their evaluated source.
type Values struct {
	DNSUpstream           string
	DefaultPolicyProfile  string
	DefaultCPUs           uint32
	DefaultMemoryMiB      uint32
	DockerVolumeSize      string
	MCPRemoteAllowedHosts string
	Extra                 map[string]string
}

// DefaultPath returns ~/.config/rheic/settings.toml, honoring XDG_CONFIG_HOME.
func DefaultPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "rheic", "settings.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "rheic", "settings.toml")
}

// Load reads the optional settings file. A missing file is not an error.
func Load(path string) (Values, error) {
	var values Values
	if path == "" {
		return values, nil
	}
	file, err := os.Open(path) // #nosec G304 -- path is the user settings location
	if errors.Is(err, os.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return values, fmt.Errorf("open settings: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return values, fmt.Errorf("stat settings: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return values, errors.New("settings file must be a regular file not writable by group or others")
	}
	if err := parse(file, &values); err != nil {
		return values, err
	}
	return values, nil
}

func parse(r io.Reader, values *Values) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("settings line %d: expected key = value", lineNumber)
		}
		key = strings.TrimSpace(key)
		value, err := parseValue(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("settings line %d: %w", lineNumber, err)
		}
		if err := applyParsedPair(values, key, value); err != nil {
			return fmt.Errorf("settings line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	return nil
}

// applyParsedPair routes one parsed key/value pair into the typed fields or
// the Extra overrides.
func applyParsedPair(values *Values, key, value string) error {
	switch key {
	case "dns_upstream", "dns.upstream":
		values.DNSUpstream = value
	case "default_policy_profile", "policy.profile":
		values.DefaultPolicyProfile = value
	case "default_cpus", "defaults.cpus":
		parsed, err := parseUint(key, value, 32)
		if err != nil {
			return err
		}
		values.DefaultCPUs = uint32(parsed) //nolint:gosec // parsed with 32 bits and validated below.
	case "default_memory_mib", "defaults.memory_mib":
		parsed, err := parseUint(key, value, 32)
		if err != nil {
			return err
		}
		values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // parsed with 32 bits and validated below.
	case "docker_volume_size", "sandbox.disk.dockerVolume":
		values.DockerVolumeSize = value
	case "mcp_remote_allowed_hosts", "mcp.remote.allowedHosts":
		values.MCPRemoteAllowedHosts = value
	default:
		if _, found := Find(key); !found {
			return fmt.Errorf("unknown key %q", key)
		}
		if values.Extra == nil {
			values.Extra = map[string]string{}
		}
		values.Extra[key] = value
	}
	return nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty value")
	}
	if raw[0] != '"' {
		return raw, nil
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return value, nil
}

func settingsEntries(values Values) []string {
	entries := make([]string, 0, 8+len(values.Extra))
	if values.DNSUpstream != "" {
		entries = append(entries, "dns_upstream = "+strconv.Quote(values.DNSUpstream))
	}
	if values.DefaultPolicyProfile != "" {
		entries = append(entries, "default_policy_profile = "+strconv.Quote(values.DefaultPolicyProfile))
	}
	if values.DefaultCPUs != 0 {
		entries = append(entries, "default_cpus = "+strconv.FormatUint(uint64(values.DefaultCPUs), 10))
	}
	if values.DefaultMemoryMiB != 0 {
		entries = append(entries, "default_memory_mib = "+strconv.FormatUint(uint64(values.DefaultMemoryMiB), 10))
	}
	if values.DockerVolumeSize != "" {
		entries = append(entries, "docker_volume_size = "+strconv.Quote(values.DockerVolumeSize))
	}
	if values.MCPRemoteAllowedHosts != "" {
		entries = append(entries, "mcp_remote_allowed_hosts = "+strconv.Quote(values.MCPRemoteAllowedHosts))
	}
	for key, value := range values.Extra {
		entries = append(entries, key+" = "+strconv.Quote(value))
	}
	sort.Strings(entries)
	return entries
}

func parseUint(key, value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return parsed, nil
}

// Save atomically writes all values. Empty values are omitted.
func Save(path string, values Values) error {
	if path == "" {
		return errors.New("settings path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create settings directory: %w", err)
	}
	body := "# Rheic host settings. Managed by rsbx settings; do not put secrets here.\n"
	if entries := settingsEntries(values); len(entries) > 0 {
		body += strings.Join(entries, "\n") + "\n"
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return fmt.Errorf("create settings temp file: %w", err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("chmod settings temp file: %w", err)
	}
	if _, err := temp.WriteString(body); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write settings: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync settings: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close settings: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace settings: %w", err)
	}
	return nil
}

// ValidateValue checks value against the entry's declared type. An empty
// value means "remove the override" and is always valid.
func ValidateValue(entry Entry, value string) error {
	if value == "" {
		return nil
	}
	switch entry.Type {
	case TypeBool:
		//nolint:goconst // the string also appears in generated catalog defaults.
		if value != "true" && value != "false" {
			return fmt.Errorf("%s must be true or false", entry.Key)
		}
	case TypeInt:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 0 {
			return fmt.Errorf("%s must be a non-negative integer", entry.Key)
		}
		if entry.Key == "daemon.log.maxAgeDays" && parsed > 3650 {
			return errors.New("daemon.log.maxAgeDays must be at most 3650")
		}
	case TypeJSON:
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			return fmt.Errorf("%s must be valid JSON: %w", entry.Key, err)
		}
	}
	return nil
}
