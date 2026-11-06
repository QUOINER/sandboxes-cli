// Code generated from the pinned sbx v0.50.1 settings matrix capture (settings ls --json plus the ls restart column); DO NOT EDIT.
package settings

// Entry describes one supported setting.
type Entry struct {
	Key         string
	Type        string
	Default     string
	Restart     bool
	Description string
}

// dockerCatalog is the pinned Docker Sandboxes settings matrix.
var dockerCatalog = []Entry{
	{Key: "browser.enabled", Type: "bool", Default: "true", Restart: false, Description: "Allow sandboxed processes to open URLs in the host browser. Disabling it also prevents in-sandbox OAuth logins that redirect to localhost."},
	{Key: "claude.remoteControl", Type: "bool", Default: "false", Restart: false, Description: "Allow Claude Code's /remote-control channel to authenticate with its own session token instead of the host credential."},
	{Key: "clipboard.imagePaste", Type: "bool", Default: "false", Restart: false, Description: "Allow sandboxed agents to read the host clipboard for image paste (Ctrl+V)."},
	{Key: "daemon.log.maxAgeDays", Type: "int", Default: "0", Restart: true, Description: "Days to keep rotated daemon logs (maximum 3650). 0 keeps them regardless of age, subject to the backup limit."},
	{Key: "daemon.log.maxBackups", Type: "int", Default: "3", Restart: true, Description: "Number of rotated daemon logs to keep. 0 keeps all, subject to the age limit."},
	{Key: "daemon.log.maxSizeMB", Type: "int", Default: "50", Restart: true, Description: "Size in MB at which daemon.log rotates (minimum 1)."},
	{Key: "diagnostics.autoUpload", Type: "string", Default: "", Restart: false, Description: "Tri-state consent for automatic diagnostics bundle upload on error: \"\" (never asked; prompts and uploads nothing), \"yes\" (accepted; upload), \"no\" (declined; never prompt again)."},
	{Key: "env.rememberHostCommands", Type: "bool", Default: "false", Restart: false, Description: "Let an approval of an environment's host commands cover later runs of the same commands, instead of asking each time."},
	{Key: "kit.allowExtractedAgents", Type: "bool", Default: "true", Restart: false, Description: "Admit the pinned kit references that replace formerly built-in agents even when kit.allowedSources does not list them, and exempt those references from kit.requireSignature. Credential trust for the fetched content is decided separately, by comparing it against the engine's compiled-in digest. Set to false to require an explicit allowlist entry."},
	{Key: "kit.allowLocalKits", Type: "bool", Default: "true", Restart: false, Description: "Allow installing kits from local directories or ZIP files. Set to false to require a remote source."},
	{Key: "kit.allowedSources", Type: "json", Default: "[\"docker.io/\"]", Restart: false, Description: "JSON array of allowed kit source prefixes (e.g. [\"docker.io/\", \"ghcr.io/docker/\"]). Use [\"*\"] to allow any remote source."},
	{Key: "kit.ignoreTransparencyLog", Type: "bool", Default: "false", Restart: false, Description: "Verify keyless kit signatures without requiring a Rekor transparency-log entry (for private kits signed with --tlog-upload=false)."},
	{Key: "kit.requireSignature", Type: "bool", Default: "false", Restart: false, Description: "Require a valid signature from a trusted signer (kit.trustedSigners) before installing a kit. The pinned kit references that replace formerly built-in agents are exempt while kit.allowExtractedAgents is true."},
	{Key: "kit.shortcuts.claude", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run claude` and `sbx create claude` resolve instead of the default kit for claude. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.claude-bedrock", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run claude-bedrock` and `sbx create claude-bedrock` resolve instead of the default kit for claude-bedrock. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.claude-vertex", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run claude-vertex` and `sbx create claude-vertex` resolve instead of the default kit for claude-vertex. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.codex", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run codex` and `sbx create codex` resolve instead of the default kit for codex. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.copilot", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run copilot` and `sbx create copilot` resolve instead of the default kit for copilot. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.cursor", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run cursor` and `sbx create cursor` resolve instead of the default kit for cursor. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.devin", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run devin` and `sbx create devin` resolve instead of the default kit for devin. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.docker-agent", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run docker-agent` and `sbx create docker-agent` resolve instead of the default kit for docker-agent. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.droid", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run droid` and `sbx create droid` resolve instead of the default kit for droid. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.gemini", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run gemini` and `sbx create gemini` resolve instead of the default kit for gemini. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.kiro", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run kiro` and `sbx create kiro` resolve instead of the default kit for kiro. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.opencode", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run opencode` and `sbx create opencode` resolve instead of the default kit for opencode. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.shortcuts.shell", Type: "string", Default: "", Restart: false, Description: "Kit reference (registry reference, oci:// or git+ URL, or absolute path) that `sbx run shell` and `sbx create shell` resolve instead of the default kit for shell. Applies to local sandboxes only. Unset to restore the default."},
	{Key: "kit.trustedSigners", Type: "json", Default: "[{\"identityRegexp\":\"^.*@docker\\\\.com$\",\"issuer\":\"https://accounts.google.com\"}]", Restart: false, Description: "JSON array of trusted signer policies (key-based {\"key\":path} or keyless {\"issuer\":...,\"identity\":...}). Defaults to Docker employee identities (*@docker.com via https://accounts.google.com)."},
	{Key: "mcp.forceLocalGateway", Type: "bool", Default: "false", Restart: true, Description: "Force the local MCP gateway even when entitled to the SaaS gateway."},
	{Key: "model.providers", Type: "json", Default: "{}", Restart: false, Description: "JSON object of inference endpoints for `sbx run --model <model> --provider <id>`, keyed by id, e.g. {\"gpubox\": {\"url\": \"http://gpubox:8000/v1\"}}. Fields: url (required, absolute http(s)), wire (\"openai\" default or \"anthropic\"), apiKeyEnv (variable llmman serve reads the API key from), name."},
	{Key: "no_proxy", Type: "string", Default: "", Restart: true, Description: "No-proxy exception list for sandbox, daemon, and supported CLI host egress (comma-separated hosts, domain suffixes, and CIDRs)."},
	{Key: "no_proxy.daemon", Type: "string", Default: "", Restart: true, Description: "No-proxy exception list for daemon and supported CLI host egress (overrides no_proxy)."},
	{Key: "no_proxy.sandbox", Type: "string", Default: "", Restart: true, Description: "No-proxy exception list for sandbox egress only (overrides no_proxy)."},
	{Key: "platform.allowExperimentalFeatures", Type: "bool", Default: "true", Restart: false, Description: "Allow experimental features."},
	{Key: "platform.images.registryMirror", Type: "string", Default: "", Restart: false, Description: "Registry mirror host for Docker Hub-resolving template and kit images (e.g. \"artifactory.corp/docker-remote\"). A bare host that is not a loopback or wildcard address also mirrors Docker Hub pulls made inside the sandbox, provided the sandbox trusts its certificate. Empty disables mirroring."},
	{Key: "platform.images.useDHI", Type: "bool", Default: "false", Restart: false, Description: "Use Docker Hardened Image (DHI) equivalents (dhi/sbx-templates) for agent template images."},
	{Key: "proxy", Type: "string", Default: "", Restart: true, Description: "Upstream proxy for sandbox, daemon, and supported CLI host egress (URL, PAC source, \"system\", or \"direct\"; empty = automatic: HTTP(S)_PROXY if set, otherwise the host OS proxy)."},
	{Key: "proxy.daemon", Type: "string", Default: "", Restart: true, Description: "Upstream proxy for daemon and supported CLI host egress (overrides proxy)."},
	{Key: "proxy.integratedAuth", Type: "bool", Default: "false", Restart: true, Description: "Enable integrated NTLM/Kerberos authentication (Windows SSPI) for sandbox, daemon, and supported CLI host egress."},
	{Key: "proxy.sandbox", Type: "string", Default: "", Restart: true, Description: "Upstream proxy for sandbox egress only (overrides proxy)."},
	{Key: "proxy.sshDirect", Type: "bool", Default: "false", Restart: false, Description: "Dial the cloud SSH gateway directly instead of through the proxy selected for CLI host egress."},
	{Key: "sandbox.disk.dockerVolume", Type: "string", Default: "10g", Restart: false, Description: "Size of a sandbox's /var/lib/docker volume (minimum 512 MiB; e.g. \"10g\"). Applies to sandboxes created after the change; existing volumes are never resized. Set DOCKER_SANDBOXES_DOCKER_SIZE to override one sandbox."},
	{Key: "skills.defaultMode", Type: "string", Default: "readonly", Restart: false, Description: "Default for an omitted --skills flag or sbx.yaml `skills:` key: \"off\", \"readonly\", or \"readwrite\". Applies to sandboxes created after the change; existing sandboxes' mounts are never retroactively changed."},
	{Key: "ssh.agentForwardingEnabled", Type: "bool", Default: "true", Restart: true, Description: "Allow sandboxes to list SSH agent keys and sign, but not add, remove or lock keys. Disabling blocks new agent connections; existing connections remain active. After enabling, restart the daemon, then restart sandboxes that started with forwarding disabled."},
	{Key: "ssh.agentSocketPath", Type: "string", Default: "", Restart: true, Description: "Optional fixed host SSH agent socket path. Empty uses each client's current SSH_AUTH_SOCK, or the native Windows OpenSSH agent pipe when that variable is unset. Existing forwarders require a daemon restart after changes."},
	{Key: "ssh.autoCreate", Type: "bool", Default: "false", Restart: true, Description: "Create a sandbox on SSH connect when it does not exist."},
	{Key: "ssh.defaultAgent", Type: "string", Default: "shell", Restart: true, Description: "Built-in agent used for SSH auto-created sandboxes."},
	{Key: "ssh.defaultTemplate", Type: "string", Default: "", Restart: true, Description: "Template image override for SSH auto-created sandboxes (agent default if empty)."},
	{Key: "ssh.workspaceRoot", Type: "string", Default: "", Restart: true, Description: "Host directory holding SSH auto-created sandbox workspaces (empty = mount-less, container-internal)."},
	{Key: "tls.allowNegativeSerial", Type: "bool", Default: "false", Restart: true, Description: "Accept server certificates with a negative serial number (needed by some TLS-inspecting proxies)."},
}

// extensionKeys are Rheic-only settings consumed by the local runtime. They
// sit beside the Docker matrix and use the same override file.
var extensionKeys = []Entry{
	{Key: "dns.upstream", Type: "string", Restart: true, Description: "DNS upstream used by sandbox gateways (HOST:PORT)"},
	{Key: "policy.profile", Type: "string", Description: "Default network policy profile for new sandboxes: deny-all, balanced, sbx-compat"},
	{Key: "defaults.cpus", Type: "int", Description: "CPU count for new sandboxes (0 = host-derived)"},
	{Key: "defaults.memory_mib", Type: "int", Description: "Memory in MiB for new sandboxes (0 = host-derived)"},
}

// Catalog returns every supported setting, Docker matrix first.
func Catalog() []Entry {
	out := make([]Entry, 0, len(dockerCatalog)+len(extensionKeys))
	out = append(out, dockerCatalog...)
	out = append(out, extensionKeys...)
	return out
}

// Find returns the catalog entry for key.
func Find(key string) (Entry, bool) {
	for _, entry := range dockerCatalog {
		if entry.Key == key {
			return entry, true
		}
	}
	for _, entry := range extensionKeys {
		if entry.Key == key {
			return entry, true
		}
	}
	return Entry{}, false
}
