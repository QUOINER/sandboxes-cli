package command

import (
	"context"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

type tuiActionClient struct {
	fakeClient
	created   []sdk.CreateRequest
	started   []string
	stopped   []string
	deleted   []string
	deleteFor []sdk.Sandbox
}

func (c *tuiActionClient) Sandboxes() sdk.SandboxService {
	return tuiActionSandboxes{client: c}
}

type tuiActionSandboxes struct {
	sdk.SandboxService
	client *tuiActionClient
}

func (s tuiActionSandboxes) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: s.client.deleteFor}, nil
}

func (s tuiActionSandboxes) Create(_ context.Context, req sdk.CreateRequest) (*sdk.Operation, error) {
	s.client.created = append(s.client.created, req)
	return &sdk.Operation{ID: "op-1"}, nil
}

func (s tuiActionSandboxes) Start(_ context.Context, id string) (*sdk.Operation, error) {
	s.client.started = append(s.client.started, id)
	return &sdk.Operation{ID: "op-start"}, nil
}

func (s tuiActionSandboxes) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	s.client.stopped = append(s.client.stopped, id)
	return &sdk.Operation{ID: "op-stop"}, nil
}

func (s tuiActionSandboxes) Delete(_ context.Context, id string, _ sdk.DeleteOptions) (*sdk.Operation, error) {
	s.client.deleted = append(s.client.deleted, id)
	return &sdk.Operation{ID: "op-delete"}, nil
}

func keyRune(r rune) *tcell.EventKey {
	return tcell.NewEventKey(tcell.KeyRune, string(r), tcell.ModNone)
}

func TestCreateFormNavigationAndValidation(t *testing.T) {
	form := newCreateFormModel()
	if form.values[4] != "." {
		t.Fatalf("default workspace = %q", form.values[4])
	}
	if err := form.validate(); err == nil {
		t.Fatal("empty name accepted")
	}
	for _, r := range "dev-sandbox" {
		form.insert(string(r))
	}
	form.move(3)
	for _, r := range "balanced" {
		form.insert(string(r))
	}
	if err := form.validate(); err != nil {
		t.Fatalf("valid form rejected: %v", err)
	}
	form.backspace()
	form.backspace()
	form.backspace()
	form.insert("xyz")
	if err := form.validate(); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestCreateFormRejectsBadNameCharacters(t *testing.T) {
	form := newCreateFormModel()
	for _, r := range "bad name!" {
		form.insert(string(r))
	}
	if err := form.validate(); err == nil {
		t.Fatal("name with space and punctuation accepted")
	}
}

func TestDashboardCreateFlowSubmitsThroughSDK(t *testing.T) {
	client := &tuiActionClient{}
	model := &dashboardModel{}
	ctx := context.Background()

	if dashboardKey(keyRune('n'), model, ctx, client) {
		t.Fatal("n must not quit the dashboard")
	}
	if model.mode != modeCreate {
		t.Fatalf("mode=%v", model.mode)
	}
	for _, r := range "tui-dev" {
		dashboardKey(keyRune(r), model, ctx, client)
	}
	dashboardKey(tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone), model, ctx, client)
	if model.mode != modeList {
		t.Fatalf("mode=%v after submit", model.mode)
	}
	if len(client.created) != 1 || client.created[0].Name != "tui-dev" || client.created[0].Workspace != "." {
		t.Fatalf("created=%+v", client.created)
	}
	if model.notice == "" {
		t.Fatal("missing confirmation notice")
	}
}

func TestDashboardDeleteConfirmsBeforeDelete(t *testing.T) {
	client := &tuiActionClient{deleteFor: []sdk.Sandbox{{ID: "sb-1", Name: "victim", State: "stopped"}}}
	model := &dashboardModel{items: client.deleteFor}
	ctx := context.Background()

	dashboardKey(keyRune('d'), model, ctx, client)
	if model.mode != modeConfirmDelete {
		t.Fatalf("mode=%v", model.mode)
	}
	dashboardKey(keyRune('n'), model, ctx, client)
	if len(client.deleted) != 0 {
		t.Fatalf("delete without confirm: %v", client.deleted)
	}
	dashboardKey(keyRune('d'), model, ctx, client)
	dashboardKey(keyRune('y'), model, ctx, client)
	if len(client.deleted) != 1 || client.deleted[0] != "sb-1" {
		t.Fatalf("deleted=%v", client.deleted)
	}
	if model.mode != modeList {
		t.Fatalf("mode=%v", model.mode)
	}
}

func TestDashboardStartStopRespectState(t *testing.T) {
	client := &tuiActionClient{deleteFor: []sdk.Sandbox{
		{ID: "sb-run", Name: "runner", State: "running"},
		{ID: "sb-halt", Name: "halted", State: "stopped"},
	}}
	model := &dashboardModel{items: client.deleteFor}
	ctx := context.Background()

	dashboardKey(keyRune('x'), model, ctx, client)
	if len(client.stopped) != 1 || client.stopped[0] != "sb-run" {
		t.Fatalf("stopped=%v", client.stopped)
	}
	model.selected = 1
	dashboardKey(keyRune('s'), model, ctx, client)
	if len(client.started) != 1 || client.started[0] != "sb-halt" {
		t.Fatalf("started=%v", client.started)
	}
}

func TestDrawCreateFormRendersFields(t *testing.T) {
	screen := newDashboardTestScreen(100, 30)
	model := &dashboardModel{mode: modeCreate, form: newCreateFormModel()}
	drawDashboard(screen, model)
	output := screen.text()
	for _, want := range []string{"NEW SANDBOX", "NAME", "AGENT", "IMAGE", "POLICY PROFILE", "WORKSPACE", "Enter create"} {
		if !strings.Contains(output, want) {
			t.Errorf("create form lacks %q", want)
		}
	}
}
