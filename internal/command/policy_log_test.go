package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func writeAuditFixture(t *testing.T, runDir, sandbox, body string) {
	t.Helper()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, sandbox+".audit.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyLogAggregatesAndLimitsAuditDecisions(t *testing.T) {
	state := t.TempDir()
	socket := filepath.Join(state, "sandboxesd.sock")
	writeAuditFixture(t, filepath.Join(state, "run"), "dev", `{"time":"2026-11-06T10:00:00Z","revision":"r1","protocol":"tcp","destination":"1.1.1.1","port":443,"action":"allowed","reason":"cidr allow","rule":"rule-a"}
{"time":"2026-11-06T10:01:00Z","revision":"r1","protocol":"tcp","destination":"example.com","port":443,"action":"denied","reason":"default deny"}
not json
`)
	writeAuditFixture(t, filepath.Join(state, "run"), "review", `{"time":"2026-11-06T10:02:00Z","sandboxId":"review","revision":"r2","protocol":"udp","destination":"8.8.8.8","port":53,"action":"allowed"}
`)
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: socket, NewClient: func(string) (sdk.Client, error) {
		return nil, errors.New("policy log does not need a daemon")
	}}
	if code := runner.Run(context.Background(), []string{"policy", "log", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var payload struct {
		Decisions []egressDecision `json:"decisions"`
		Malformed int              `json:"malformed"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if len(payload.Decisions) != 3 || payload.Malformed != 1 {
		t.Fatalf("decisions=%d malformed=%d", len(payload.Decisions), payload.Malformed)
	}
	if payload.Decisions[0].Time > payload.Decisions[2].Time {
		t.Fatalf("decisions not time-ordered: %+v", payload.Decisions)
	}
	if payload.Decisions[1].SandboxID != "dev" {
		t.Fatalf("fallback sandbox missing: %+v", payload.Decisions[1])
	}
}

func TestPolicyLogFiltersBySandboxAndLimit(t *testing.T) {
	state := t.TempDir()
	socket := filepath.Join(state, "sandboxesd.sock")
	var lines string
	for i := 0; i < 30; i++ {
		lines += fmt.Sprintf(`{"time":"2026-11-06T10:%02d:00Z","revision":"r","protocol":"tcp","destination":"1.1.1.1","port":443,"action":"allowed"}`+"\n", i)
	}
	writeAuditFixture(t, filepath.Join(state, "run"), "dev", lines)
	writeAuditFixture(t, filepath.Join(state, "run"), "other", `{"time":"2026-11-06T11:00:00Z","revision":"r","protocol":"tcp","destination":"2.2.2.2","port":80,"action":"denied"}`+"\n")
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Socket: socket, NewClient: func(string) (sdk.Client, error) {
		return nil, errors.New("policy log does not need a daemon")
	}}
	runner.Out = &bytes.Buffer{}
	var out bytes.Buffer
	runner.Out = &out
	if code := runner.Run(context.Background(), []string{"policy", "log", "dev", "--limit", "5"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "2.2.2.2") {
		t.Fatalf("sandbox filter not applied: %q", out.String())
	}
	if got := strings.Count(out.String(), "allowed"); got != 5 {
		t.Fatalf("limit rows=%d, want 5: %q", got, out.String())
	}
}

func TestPolicyLogRejectsBadFlags(t *testing.T) {
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Socket: filepath.Join(t.TempDir(), "run", "sandboxesd.sock")}
	if code := runner.Run(context.Background(), []string{"policy", "log", "--type", "filesystem"}); code != 2 {
		t.Fatalf("exit=%d", code)
	}
	if code := runner.Run(context.Background(), []string{"policy", "log", "--limit", "-1"}); code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestPolicyInspectMatchesRuleIDBeforeSandbox(t *testing.T) {
	rule := policyRuleOutput{RuleID: "rule-xyz", Scope: "global", ResourceType: "network", Action: "allow", Protocol: "tcp", CIDR: "1.1.1.1/32", Port: 443}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: filepath.Join(t.TempDir(), "sandboxesd.sock"), NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: policyInspectSandbox{rule: rule}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"policy", "inspect", "rule-xyz"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "rule-xyz") || !strings.Contains(out.String(), "1.1.1.1/32") {
		t.Fatalf("output=%q", out.String())
	}
}

type policyInspectSandbox struct {
	fakeSandbox
	rule policyRuleOutput
}

func (s policyInspectSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{
		ID:    "sb-1",
		Name:  "dev",
		Allow: []sdk.NetworkRule{{RuleID: s.rule.RuleID, CIDR: s.rule.CIDR, Port: s.rule.Port}},
	}}}, nil
}
