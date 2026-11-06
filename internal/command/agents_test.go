package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestKimiAgentSpec(t *testing.T) {
	if agentImage("kimi") == "" || agentCommand("kimi") != "kimi" {
		t.Fatalf("image=%q command=%q", agentImage("kimi"), agentCommand("kimi"))
	}
	if err := validateRunAgent("kimi"); err != nil {
		t.Fatalf("kimi rejected: %v", err)
	}
	if !isAgentName("kimi") {
		t.Fatal("kimi is not an agent name")
	}
}

func TestCreateKimiUsesDefaultImage(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--name", "kimi", "kimi", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Agent != "kimi" || sandbox.request.Image != agentImage("kimi") {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestRunKimiUsesAgentCommand(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "kimi", "kimi", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Agent != "kimi" || sandboxes.created.Image != agentImage("kimi") {
		t.Fatalf("created=%+v", sandboxes.created)
	}
	if len(sessions.req.Argv) == 0 || sessions.req.Argv[0] != "kimi" {
		t.Fatalf("argv=%v", sessions.req.Argv)
	}
}

func TestAgentRegistryPreviewAndUnsupported(t *testing.T) {
	if !strings.HasPrefix(agentImage("codex"), "docker.io/docker/sandbox-templates@sha256:") || agentCommand("codex") != "codex" {
		t.Fatalf("codex image=%q command=%q", agentImage("codex"), agentCommand("codex"))
	}
	if !agentDocker("codex") {
		t.Fatal("codex must enable docker profile")
	}
	var image, profile string
	var docker bool
	applyAgentDefaults("codex", &image, &docker)
	if !strings.HasPrefix(image, "docker.io/docker/sandbox-templates@sha256:") || profile != "" || !docker {
		t.Fatalf("codex defaults image=%q profile=%q docker=%v", image, profile, docker)
	}
	if err := validateRunAgent("codex"); err != nil {
		t.Fatalf("preview codex rejected: %v", err)
	}
	if err := validateRunAgent("cursor"); err != nil {
		t.Fatalf("preview cursor rejected: %v", err)
	}
	if err := validateRunAgent("cline"); err == nil {
		t.Fatal("unsupported cline accepted")
	}
	if err := validateRunAgent("missing"); err == nil {
		t.Fatal("unknown agent accepted")
	}
	if !isAgentName("kimi") || !isAgentName("cline") || isAgentName("missing") {
		t.Fatal("isAgentName registry mismatch")
	}
}

func TestDockerBuiltinAgentsAreLaunchableAndPinned(t *testing.T) {
	want := []string{"claude", "codex", "copilot", "cursor", "devin", "docker-agent", "droid", "gemini", "kiro", "opencode", "shell"}
	registry, err := agentRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range want {
		spec, ok := registry.Lookup(name)
		if !ok || !spec.Launchable() {
			t.Fatalf("agent %q missing or not launchable: %+v, found=%t", name, spec, ok)
		}
		if !strings.Contains(spec.Image, "@sha256:") {
			t.Errorf("agent %q image is not digest-pinned: %q", name, spec.Image)
		}
		if !strings.HasPrefix(spec.Image, "docker.io/docker/sandbox-templates@sha256:") {
			t.Errorf("agent %q image is not fully qualified for containerd: %q", name, spec.Image)
		}
		if !spec.Docker {
			t.Errorf("agent %q does not select the guest Docker profile", name)
		}
		if spec.Status != "preview" {
			t.Errorf("agent %q status=%q; changed upstream image must remain preview pending live VM acceptance", name, spec.Status)
		}
	}
}

func TestCreateUsesPinnedDockerImagesAndDockerProfile(t *testing.T) {
	for _, name := range []string{"claude", "codex", "copilot", "cursor", "devin", "docker-agent", "droid", "gemini", "kiro", "opencode", "shell"} {
		t.Run(name, func(t *testing.T) {
			sandbox := &recordingCreateSandbox{}
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
				return fakeClient{sandbox: sandbox}, nil
			}}
			if code := runner.Run(context.Background(), []string{"create", "--name", name, name}); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if sandbox.request.Agent != name || sandbox.request.Image != agentImage(name) || !sandbox.request.Privileged {
				t.Fatalf("request=%+v", sandbox.request)
			}
		})
	}
}

func TestRunArgvMatchesDockerArgumentOverrideRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "default", want: []string{"claude", "--dangerously-skip-permissions"}},
		{name: "flag extends defaults", args: []string{"--continue"}, want: []string{"claude", "--dangerously-skip-permissions", "--continue"}},
		{name: "subcommand replaces defaults", args: []string{"login", "--use-device-flow"}, want: []string{"login", "--use-device-flow"}},
	} {
		if got := runArgv("claude", tc.args); strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("%s: argv=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDockerBuiltinAgentDefaultArgvAndOverrides(t *testing.T) {
	tests := []struct {
		name    string
		command []string
	}{
		{name: "claude", command: []string{"claude", "--dangerously-skip-permissions"}},
		{name: "codex", command: []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}},
		{name: "copilot", command: []string{"copilot", "--yolo"}},
		{name: "cursor", command: []string{"cursor-agent", "--yolo"}},
		{name: "devin", command: []string{"devin", "--permission-mode", "dangerous", "--respect-workspace-trust=false"}},
		{name: "docker-agent", command: []string{"docker-agent", "run", "--yolo"}},
		{name: "droid", command: []string{"droid"}},
		{name: "gemini", command: []string{"gemini", "--yolo"}},
		{name: "kiro", command: []string{"kiro", "chat", "--trust-all-tools"}},
		{name: "opencode", command: []string{"opencode"}},
		{name: "shell", command: []string{"bash", "-l"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := runArgv(tc.name, nil); strings.Join(got, "\x00") != strings.Join(tc.command, "\x00") {
				t.Fatalf("default argv=%q, want %q", got, tc.command)
			}
			flagArgs := []string{"--help"}
			wantExtended := append(append([]string(nil), tc.command...), flagArgs...)
			if got := runArgv(tc.name, flagArgs); strings.Join(got, "\x00") != strings.Join(wantExtended, "\x00") {
				t.Errorf("flag argv=%q, want %q", got, wantExtended)
			}
			replacement := []string{"login", "--device"}
			if got := runArgv(tc.name, replacement); strings.Join(got, "\x00") != strings.Join(replacement, "\x00") {
				t.Errorf("subcommand argv=%q, want replacement %q", got, replacement)
			}
		})
	}
}

func TestAgentsListShowsLaunchableDockerBaselineWithoutDaemon(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
	if code := runner.Run(context.Background(), []string{commandAgents, "ls", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var rows []templateOutput
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decode agent list: %v; output=%s", err, out.String())
	}
	for _, name := range []string{"claude", "codex", "copilot", "cursor", "devin", "docker-agent", "droid", "gemini", "kiro", "opencode", "shell"} {
		found := false
		for _, row := range rows {
			if row.Name == name {
				found = true
				if row.Status == "unsupported" {
					t.Errorf("%s is listed as unsupported", name)
				}
				break
			}
		}
		if !found {
			t.Errorf("agent list missing %q", name)
		}
	}
}

func TestPrivilegedPlumbing(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--docker", "shell"}); code != 0 {
		t.Fatalf("create exit=%d output=%q", code, out.String())
	}
	if !sandbox.request.Privileged {
		t.Fatal("create did not pass privileged")
	}
}
