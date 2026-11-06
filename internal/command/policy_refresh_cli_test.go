package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type policyRefreshFake struct {
	fakeClient
	refreshed   int
	resetCalled int
	allow       []sdk.NetworkRule
	deny        []sdk.NetworkRule
	err         error
}

func (p *policyRefreshFake) PolicyService() sdk.PolicyService { return p }

func (p *policyRefreshFake) Refresh(context.Context) (int, error) {
	p.refreshed++
	if p.err != nil {
		return 0, p.err
	}
	return 2, nil
}

func (p *policyRefreshFake) ResetGlobal(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, string, error) {
	p.resetCalled++
	return nil, nil, "deny-all", nil
}

func (p *policyRefreshFake) GetGlobalPolicy(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return p.allow, p.deny, nil
}

func (p *policyRefreshFake) Check(context.Context, string, string, string, string, uint16) (sdk.PolicyDecision, error) {
	return sdk.PolicyDecision{}, errors.New("not implemented")
}

func (p *policyRefreshFake) UpdatePolicy(context.Context, string, []sdk.NetworkRule, []sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}

func (p *policyRefreshFake) MutatePolicy(context.Context, string, string, sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}

func (p *policyRefreshFake) GetPolicyProfile(context.Context) (string, error) { return "deny-all", nil }

func (p *policyRefreshFake) SetPolicyProfile(_ context.Context, profile string) (string, error) {
	return profile, nil
}

func (p *policyRefreshFake) MutateGlobalPolicy(context.Context, string, sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return p.allow, p.deny, nil
}

func runPolicyRPC(t *testing.T, fake *policyRefreshFake, stdin string, args ...string) (*bytes.Buffer, int) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(stdin), Socket: t.TempDir() + "/sandboxesd.sock",
		NewClient: func(string) (sdk.Client, error) { return fake, nil }}
	return &out, runner.Run(context.Background(), append([]string{"policy"}, args...))
}

func TestPolicyRefreshCallsDaemon(t *testing.T) {
	fake := &policyRefreshFake{}
	out, code := runPolicyRPC(t, fake, "", "refresh")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if fake.refreshed != 1 || !strings.Contains(out.String(), "refreshed policy on 2 running sandbox(s)") {
		t.Fatalf("refreshed=%d output=%q", fake.refreshed, out.String())
	}
}

func TestPolicyResetRequiresConfirmationAndKeepsSandboxRules(t *testing.T) {
	fake := &policyRefreshFake{allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "192.0.2.0/24"}}}
	out, code := runPolicyRPC(t, fake, "n\n", "reset")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if fake.resetCalled != 0 || !strings.Contains(out.String(), "reset canceled") {
		t.Fatalf("resetCalled=%d output=%q", fake.resetCalled, out.String())
	}
	out, code = runPolicyRPC(t, fake, "y\n", "reset")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if fake.resetCalled != 1 || !strings.Contains(out.String(), "reset global policy (profile=deny-all, allow=0, deny=0)") {
		t.Fatalf("resetCalled=%d output=%q", fake.resetCalled, out.String())
	}
	out, code = runPolicyRPC(t, fake, "", "reset", "--force")
	if code != 0 || fake.resetCalled != 2 {
		t.Fatalf("exit=%d resetCalled=%d output=%q", code, fake.resetCalled, out.String())
	}
}

func TestPolicyRefreshSurfacesDaemonErrors(t *testing.T) {
	fake := &policyRefreshFake{err: errors.New("gateway reload rejected")}
	_, code := runPolicyRPC(t, fake, "", "refresh")
	if code != 1 {
		t.Fatalf("exit=%d", code)
	}
}
