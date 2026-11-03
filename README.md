# sandboxes-cli

Status: pre-alpha.

## Import path migration

The canonical Go module path is now `github.com/lickren/sandboxes-cli` (previously `github.com/quoiner/sandboxes-cli`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Command-line and terminal client. Uses sandboxes-go-sdk; does not import daemon
internals. The read-only dashboard uses `github.com/gdamore/tcell/v3` as its
terminal runtime. Bubble Tea is not used. TUI remains a thin view/input layer;
non-interactive commands retain stable text and JSON output.

## Migrating from `qsbx`

The executable is now named `lsbx`. Update scripts, aliases, CI jobs, and
package-manager references from `qsbx` to `lsbx`, then regenerate shell
completions with `lsbx completion <shell>`. The daemon socket and sandbox data
are unchanged. No `qsbx` compatibility binary or Docker-owned `sbx` alias is
installed.

## Commands

```sh
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run shell .
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run shell . /path/to/docs:ro
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --detach --name dev --cpus 2 --memory 2g --publish 8080:3000 shell .
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --name dev -- -c 'printf reattach'
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --rm --name dev -- -c 'exit 0'
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" exec -it dev /bin/sh
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" exec -e FOO=bar --env-file .env -u 1000:1001 dev env
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" cp ./file.txt dev:/tmp/file.txt
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" cp dev:/tmp/result.txt ./result.txt
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" create --name dev shell . /docs:ro --publish 8080:3000
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" create shell .   # auto-generated name
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ports dev
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls --format json
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls -q
lsbx tui
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" get <name-or-id>
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" start one two
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" stop one two
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm [--force] one two
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm --all --force
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --dry-run
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --dry-run --filter until=168h
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --force
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" diagnose
lsbx completion bash > /tmp/lsbx-completion.bash
source /tmp/lsbx-completion.bash
lsbx --socket "$HOME/.sandboxes/sandboxesd.sock" wait <operation-id>
lsbx secret set --registry ghcr.io --username <registry-user>
lsbx secret set openai --sandbox dev          # hidden prompt; value stays in host keychain
lsbx secret import --all
lsbx secret ls
lsbx secret rm openai --sandbox dev
lsbx settings ls
lsbx settings set dns.upstream 1.1.1.1:53
lsbx settings set policy.profile balanced
lsbx attach dev
lsbx kit inspect examples/kits/codex-go.yaml
lsbx run --kit examples/kits/codex-go.yaml
```

The `lsbx tui` dashboard draws the Lickren ember mark directly in the terminal,
with the organization name, brand colors, and sandbox status. The scalable SVG
mark is in `assets/lickren-mark.svg`.

`lsbx create` mirrors the Docker grammar `create AGENT [PATH...]` with optional
`--name NAME`; a missing PATH creates a mountless sandbox, and PATHs accept the
`:ro` suffix. The legacy `create NAME` and repeated `--workspace` forms remain
supported. `lsbx run` creates a sandbox (or reuses `--name`), starts it if needed, and
attaches an interactive shell. The default workspace is the current directory;
multiple PATH arguments may follow the agent, with an optional `:ro` suffix.
`--deny-write PATH` adds a read-only subpath mount, so a writable parent can
hold a protected child. `--detach` creates and starts without attaching
and prints the sandbox ID. `--cpus`/`--memory` apply only when creating;
reusing an existing sandbox warns and keeps its resources. `-e/--env` and
`--env-file` add session env overrides. `--rm` removes the sandbox after the
session (rejected with `--detach`). Only the `shell` agent is implemented;
`kimi` and `codex` use public pinned GHCR images (see `agents/kimi/` and the
embedded registry). `gemini` and `opencode` are preview entries using their
official image names; `dsh` serves the pinned DeepSeek Harness web UI on guest
port 8080 and publishes it on a loopback port by default. `claude`, `cline` and
the remaining agents are explicitly unsupported until an image/auth contract
exists. The embedded registry is `internal/agent/registry.yaml`. Multiple workspaces are supported; a
`:ro` suffix mounts a directory read-only. `--publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]`
may be repeated when creating, with loopback `HOST_IP` limited to `127.0.0.1` and
`::1` (IPv6 uses brackets, e.g. `[::1]:8080:80/tcp6`); `lsbx ports SANDBOX`
lists the stored bindings; `ports --publish ...` / `--unpublish ...` change them
live; omitting `HOST_PORT` allocates an ephemeral host port on the selected
loopback IP.
`--allow-network CIDR[:PORT]` and `--deny-network CIDR[:PORT]` (optional `udp:`
prefix) add create-time IPv4 egress rules; the default remains deny.
`--policy-profile deny-all|balanced|sbx-compat` selects an egress preset
(balanced: 80/443 + DNS; sbx-compat: all IPv4 network); the global default is
`deny-all` and settings can change it. `lsbx policy ls [SANDBOX]` lists global
and sandbox rules with `rule_id`, scope, action, protocol, target and port.
`policy allow|deny|rm network [--sandbox NAME] TARGET` accepts an IPv4 CIDR or
a domain (`example.com`, `*.example.com`, `**.example.com`, single-label
`?`/`[]` globs), with an optional `:PORT`; deny wins across scopes and global
changes are applied live to running sandboxes. Domain rules require a DNS
upstream and resolve only allowlisted names; a domain rule is enforced after a
DNS answer is bound to its IPs. `policy check network` evaluates CIDR or domain
targets (exit 0 allow, 1 deny). `reset`, `refresh`, approvals, HTTP methods and
filesystem rules are not implemented. TCP and UDP are supported with explicit
or ephemeral host ports; an occupied host port is rejected at create and
dynamic updates reconcile gvproxy's forwarders without restarting the VM.
Loopback IPv4/IPv6 bindings are supported; public bindings are rejected.
Local kits (`--kit FILE`) can set agent, image, profile and mounts. A
`workspace.seed` git URL is cloned once into the host cache with hooks disabled
and mounted as the workspace; signatures and MCP allowlists still fail closed. Reusing a `--name` with an
explicitly different workspace set/mode fails instead of silently ignoring the
mounts.
`lsbx exec -i/-t/-it` supports stdin, separate stdout/stderr, terminal size and
resize, and returns the guest exit status. Missing commands exit 127, non-executable
paths 126, sandbox/runtime errors 125, and signal exits use 128+signal
(`137` SIGKILL, `143` SIGTERM). Host-to-guest interactive signal forwarding is
not implemented. `-e/--env KEY=VALUE` and repeated
`--env-file FILE` add explicit environment overrides; `-e NAME` copies exactly
that one host variable when set (unset names are skipped). No other host
variables are read. The last duplicate wins. `-u/--user` accepts
numeric `uid[:gid]` or a guest user/group name (`root`, `nobody:nogroup`); a
bare uid keeps the image/process GID. Names are resolved by a short root probe
inside the guest using `id` and `/etc/group`, and unknown names fail closed.
Environment values
can be visible in host process arguments when passed with `-e`; do not put
secrets in argv (prefer a bounded, permission-restricted env file).

`lsbx attach [--shell] SANDBOX` starts a stopped sandbox and opens its agent
session. `lsbx settings ls|get|set|unset` manages
`~/.config/klorq/settings.toml` (`dns.upstream`, `policy.profile`,
`defaults.cpus`, `defaults.memory_mib`, `sandbox.disk.dockerVolume`); DNS and
daemon-owned consumers need a daemon restart. `lsbx secret` stores service API
keys and registry credentials in the host keychain. Service secret values are
not written to SQLite, logs or argv. `-e KEY=${secret:service}` is resolved by
the daemon at exec time; sandbox scope wins over global. `${proxy:service}` is reserved for a host proxy but currently fails closed: the
pinned guest network lacks a reliable guest-to-host route for an arbitrary
loopback listener. Use direct secret env only for agents you trust with the
key.

`lsbx cp` copies regular files and directory trees in either direction; exactly
one side is `SANDBOX:PATH` with an absolute guest path. A guest destination
ending in `/` or an existing guest directory, and an existing host directory,
are used as containers.
Archives are streamed through an exec session; guest-to-host extraction uses
`os.Root`, rejects traversal/symlink/hardlink/special entries, and bounds entry
count (100000) and size (4 GiB). Source symlinks are rejected by default; `-L/--follow-link` follows source
symlinks, including nested file and directory links. If the local source is
inside a sandbox workspace, no followed link may escape that workspace
(including when the workspace itself is reached through a symlink); cycles and
special files fail closed.

`lsbx diagnose` checks the socket path, calls `List` with a five-second deadline,
and reports sandbox counts; `--json` emits the same report for automation. It
does not diagnose containerd, image, gateway, or credential state yet.
`lsbx stop`/`start`, `rm` and `prune` accept `--format table|json|yaml` and
`--json`; structured output carries operation records (or sandbox candidates
for `prune --dry-run`).

`lsbx ls` retrieves all pages; `--limit` controls the page size. `--format`
accepts `table`, `json` or `yaml`; `--json` is the JSON shorthand, and `-q`
prints names only. JSON/YAML include `name`, `id`, `agent`, `status`, `image`,
`agent`, `status`, `last_used_at`, `workspaces`, `detached`, `cpus`, `memory_mib`,
`generation`, `created_at` and `updated_at`. The table is Docker-like:
`SANDBOX AGENT STATUS PORTS WORKSPACE CREATED`.
The local store does not record an agent yet, so `agent` is empty; Docker's
`last_used_at` and `detached` fields are not emitted. `lsbx get` resolves a name
or ID. `stop`/`start`/`rm` accept multiple names; `rm --all --force` removes every
sandbox after the explicit force flag. `rm` and `prune` require a
terminal confirmation unless `--force` is passed; `prune` removes stopped
sandboxes only, with `--dry-run` to preview and `--filter until=TIMESTAMP|DURATION`
to select sandboxes stopped before that point (RFC 3339, Unix seconds or a
non-negative Go duration relative to now). `lsbx wait` returns a nonzero exit
status when the operation finishes in a failed state.

`lsbx secret set --registry` prompts for the password without echo. For automation, pipe a
token through stdin with `--password-stdin`; never pass it as an argument or
environment variable. Credentials are stored in the host OS credential vault
with host-only scope by default. `--all-sandboxes` and `--sandbox NAME` store
separate scoped entries. `lsbx secret rm --registry` removes the selected entry.

Registry credentials previously managed with `lsbx login --registry` and
`lsbx logout --registry` are now managed with `lsbx secret set --registry`,
`lsbx secret ls` and `lsbx secret rm --registry`; existing keychain entries do
not need to be moved, but entries created before the index was introduced are
not listed until they are re-saved.
`lsbx login` and `lsbx logout` are reserved for Docker account authentication,
using the same Docker public device-flow client as Docker CLI and Docker
Sandboxes. Login starts device authorization at Docker, opens the browser,
waits for approval, exchanges the grant for a Docker Hub PAT, and stores the
credentials in the native host vault. No Klorq OAuth registration is needed.
For headless login, use `lsbx login --username USER --password-stdin` and pipe a
Docker Hub password or personal access token into stdin. The daemon validates it
with Docker Hub before storing it; the token is never accepted as a command-line
argument, printed, or written into the OAuth account record.
Existing Docker Hub registry entries cause login to fail instead of being
overwritten. Authenticated sandbox registry pulls are not connected to the
guest network path yet.

`lsbx logout` asks before stopping running local sandboxes. `--force` skips the
prompt, stops only sandboxes owned by the selected local daemon, then removes
the OAuth-owned Docker Hub credentials and requests provider token revocation.
Registry credentials created separately with `lsbx secret set` are preserved.
If the provider cannot revoke a refresh token, the CLI reports that local
credentials were removed but remote revocation did not complete.

Registry secret storage does not currently validate credentials with the
registry or enable authenticated pulls from a sandbox. Registry broker and
policy enforcement are still under implementation; the command says so on
success.

`SANDBOXES_SOCKET` can replace the `--socket` flag. Klorq commands and examples use `lsbx`; `sandboxes` is only the repository name. Docker Sandboxes commands are written as `sbx ...` only when explicitly discussing Docker's original product. A Klorq `sbx` compatibility alias is not installed by default; it requires that `command -v sbx` be empty and explicit user consent.

## Development

Requires Go 1.27.

```sh
make test
make build
```

For local development with the sibling daemon checkout and `modules/go.work`,
`make dev-bundle` builds `dist/lsbx` and `dist/sandboxesd`. Start the daemon
in a terminal with `dist/sandboxesd`, then use `dist/lsbx` in another terminal.
This bundle currently starts the state-only daemon: it does not install a
service, configure a VM runtime, or provide account OAuth. It is not a release
package; releases must build against tagged dependencies.
