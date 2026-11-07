package command

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type fakeMCPService struct {
	list                                    []sdk.MCPServer
	registerCalls, approvalCalls, callCalls int
	challenge                               bool
}

func (f *fakeMCPService) List(context.Context, string) ([]sdk.MCPServer, error) { return f.list, nil }
func (f *fakeMCPService) Call(context.Context, string, string, string, json.RawMessage) (json.RawMessage, error) {
	f.callCalls++
	if f.challenge {
		return nil, &sdk.MCPApprovalRequiredError{ApprovalID: "challenge-1", Reason: "host tool"}
	}
	return json.RawMessage(`{"content":[]}`), nil
}
func (f *fakeMCPService) ApproveCall(context.Context, string) (json.RawMessage, error) {
	f.approvalCalls++
	return json.RawMessage(`{"content":[]}`), nil
}
func (f *fakeMCPService) Register(context.Context, sdk.MCPServerConfig) (*sdk.MCPRegistration, error) {
	f.registerCalls++
	return &sdk.MCPRegistration{ApprovalID: "registration-1", ApprovalRequired: true}, nil
}
func (f *fakeMCPService) ApproveRegistration(context.Context, string) (*sdk.MCPServer, error) {
	f.approvalCalls++
	return &sdk.MCPServer{Name: "fixture"}, nil
}
func (f *fakeMCPService) Remove(context.Context, string) (bool, error) { return true, nil }

type mcpFakeClient struct {
	fakeClient
	mcp sdk.MCPService
}

func (c mcpFakeClient) MCPService() sdk.MCPService { return c.mcp }

func TestMCPListUsesExistingCommandTreeAndFlagGrammar(t *testing.T) {
	service := &fakeMCPService{list: []sdk.MCPServer{{Name: "fixture", Gateway: "local", Transport: "stdio", Usable: true}}}
	var out, stderr strings.Builder
	runner := &Runner{Out: &out, Err: &stderr, NewClient: func(string) (sdk.Client, error) { return mcpFakeClient{mcp: service}, nil }}
	if code := runner.Run(context.Background(), []string{"mcp", "ls", "--quiet"}); code != 0 || out.String() != "fixture\n" {
		t.Fatalf("code=%d output=%q stderr=%q", code, out.String(), stderr.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"mcp", "ls", "--format", "json"}); code != 0 || !strings.Contains(out.String(), `"name":"fixture"`) {
		t.Fatalf("code=%d output=%q stderr=%q", code, out.String(), stderr.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"mcp", "ls", "--format", "yaml"}); code != 0 || !strings.Contains(out.String(), "name: fixture") {
		t.Fatalf("yaml code=%d output=%q stderr=%q", code, out.String(), stderr.String())
	}
	stderr.Reset()
	if code := runner.Run(context.Background(), []string{"mcp", "ls", "--bogus"}); code != 1 || !strings.Contains(stderr.String(), "unknown flag: --bogus") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestMCPArgsFlagUsesCSVQuoting(t *testing.T) {
	var got mcpArgsFlag
	if err := got.Set(`--config,"path,with,commas",--verbose`); err != nil {
		t.Fatal(err)
	}
	want := mcpArgsFlag{"--config", "path,with,commas", "--verbose"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestMCPApprovalPromptsHideArgumentValues(t *testing.T) {
	callArgs := map[string]json.RawMessage{"query": json.RawMessage(`"synthetic-secret"`), "limit": json.RawMessage(`2`)}
	callPrompt := mcpCallApprovalMessage("fixture", "search", "sb-owned", callArgs)
	if strings.Contains(callPrompt, "synthetic-secret") || !strings.Contains(callPrompt, "argument fields: 2 (values hidden)") {
		t.Fatalf("call prompt exposed values or omitted count: %q", callPrompt)
	}
	registrationPrompt := mcpRegistrationApprovalMessage("fixture", "/usr/bin/fixture", []string{"--value", "synthetic-secret", "--stdio"}, "/tmp")
	if strings.Contains(registrationPrompt, "synthetic-secret") || !strings.Contains(registrationPrompt, "argument count: 3 (values hidden") {
		t.Fatalf("registration prompt exposed values or omitted count: %q", registrationPrompt)
	}
}

func TestMCPHostCommandsDocumentSecretAndApprovalLimits(t *testing.T) {
	var out, stderr strings.Builder
	runner := &Runner{Out: &out, Err: &stderr, In: strings.NewReader("")}
	if code := runner.Run(context.Background(), []string{"mcp", "add", "--help"}); code != 0 || !strings.Contains(stderr.String(), "do not put secrets") {
		t.Fatalf("mcp add help code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := runner.Run(context.Background(), []string{"mcp", "call", "--help"}); code != 0 || !strings.Contains(stderr.String(), "values are hidden") {
		t.Fatalf("mcp call help code=%d stderr=%q", code, stderr.String())
	}
}

func TestMCPCallAndRegistrationNeverApproveWithoutTerminal(t *testing.T) {
	service := &fakeMCPService{challenge: true}
	clientCalls := 0
	var out, stderr strings.Builder
	runner := &Runner{Out: &out, Err: &stderr, In: strings.NewReader("yes\n"), NewClient: func(string) (sdk.Client, error) { clientCalls++; return mcpFakeClient{mcp: service}, nil }}
	if code := runner.Run(context.Background(), []string{"mcp", "call", "sb-owned", "fixture", "tool", "--args", `{"x":1}`}); code != 1 || service.approvalCalls != 0 || service.callCalls != 0 || clientCalls != 0 {
		t.Fatalf("call code=%d calls=%d approvals=%d stderr=%q", code, service.callCalls, service.approvalCalls, stderr.String())
	}
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runner.Run(context.Background(), []string{"mcp", "add", "fixture", "--command", command}); code != 1 || service.registerCalls != 0 || service.approvalCalls != 0 || clientCalls != 0 {
		t.Fatalf("add code=%d register=%d approvals=%d stderr=%q", code, service.registerCalls, service.approvalCalls, stderr.String())
	}
}

func TestReorderFlagArgsPreservesExistingPositionalsAndAgentArgs(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		values map[string]bool
		want   []string
	}{
		{name: "flags after positional", args: []string{"sandbox", "--format", "json", "--quiet"}, values: map[string]bool{"--format": true}, want: []string{"--format", "json", "--quiet", "sandbox"}},
		{name: "agent args after separator", args: []string{"--name", "sample", "agent", ".", "--", "--help", "-x"}, values: map[string]bool{"--name": true}, want: []string{"--name", "sample", "agent", ".", "--help", "-x"}},
		{name: "equals values remain intact", args: []string{"sandbox", "--args={\"x\":1}"}, values: map[string]bool{"--args": true}, want: []string{"--args={\"x\":1}", "sandbox"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reorderFlagArgs(tc.args, tc.values); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v want %#v", got, tc.want)
			}
		})
	}
}

func TestPreviousRootCommandContractsRemainReachable(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{{[]string{"version"}, 0}, {[]string{"unknown"}, 2}, {[]string{"create", "--bogus"}, 1}} {
		var out, stderr strings.Builder
		runner := &Runner{Out: &out, Err: &stderr}
		if got := runner.Run(context.Background(), tc.args); got != tc.want {
			t.Errorf("%v exit=%d want %d output=%q", tc.args, got, tc.want, stderr.String())
		}
	}
}
