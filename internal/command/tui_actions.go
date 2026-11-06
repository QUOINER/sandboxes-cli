package command

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

type dashboardMode int

const (
	modeList dashboardMode = iota
	modeCreate
	modeConfirmDelete
)

var createFormFields = []string{"NAME", "AGENT", "IMAGE", "POLICY PROFILE", "WORKSPACE"}

// createFormModel is the interactive create flow shown when the dashboard
// opens, matching the sbx TUI landing. Field values are validated before the
// SDK create call.
type createFormModel struct {
	values []string
	focus  int
	err    string
}

func newCreateFormModel() createFormModel {
	values := make([]string, len(createFormFields))
	values[4] = "."
	return createFormModel{values: values}
}

func (m *createFormModel) move(delta int) {
	m.focus = (m.focus + delta + len(createFormFields)) % len(createFormFields)
}

func (m *createFormModel) insert(text string) {
	if m.focus < 0 || m.focus >= len(m.values) || text == "" {
		return
	}
	if len(m.values[m.focus])+len(text) > 63 {
		return
	}
	m.values[m.focus] += text
	m.err = ""
}

func (m *createFormModel) backspace() {
	if m.focus < 0 || m.focus >= len(m.values) {
		return
	}
	value := m.values[m.focus]
	if value == "" {
		return
	}
	runes := []rune(value)
	m.values[m.focus] = string(runes[:len(runes)-1])
	m.err = ""
}

// validate checks the form before submission.
func (m *createFormModel) validate() error {
	name := strings.TrimSpace(m.values[0])
	if name == "" {
		return errors.New("name is required")
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return errors.New("name may contain letters, digits, -, _ and . only")
		}
	}
	profile := strings.TrimSpace(m.values[3])
	switch profile {
	case "", policyProfileDenyAll, policyProfileBalanced, policyProfileCompat:
	default:
		return errors.New("policy profile must be deny-all, balanced or sbx-compat")
	}
	workspace := strings.TrimSpace(m.values[4])
	if workspace == "" {
		return errors.New("workspace is required")
	}
	return nil
}

func (m *createFormModel) createRequest() sdk.CreateRequest {
	return sdk.CreateRequest{
		Name:          strings.TrimSpace(m.values[0]),
		Agent:         strings.TrimSpace(m.values[1]),
		Image:         strings.TrimSpace(m.values[2]),
		PolicyProfile: strings.TrimSpace(m.values[3]),
		Workspace:     strings.TrimSpace(m.values[4]),
	}
}

// dashboardKeyInCreate handles one key in create mode. It returns done=true
// when the flow finished (submitted or canceled) and the model should go
// back to list mode.
func dashboardKeyInCreate(event *tcell.EventKey, model *dashboardModel) (done bool) {
	form := &model.form
	switch event.Key() {
	case tcell.KeyEscape:
		model.notice = "create canceled"
		return true
	case tcell.KeyTab, tcell.KeyDown:
		form.move(1)
		return false
	case tcell.KeyBacktab, tcell.KeyUp:
		form.move(-1)
		return false
	case tcell.KeyEnter:
		if err := form.validate(); err != nil {
			form.err = err.Error()
			return false
		}
		model.pendingCreate = form.createRequest()
		return true
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		form.backspace()
		return false
	case tcell.KeyRune:
		form.insert(event.Str())
		return false
	}
	return false
}

// submitCreate calls the SDK create and start, then refreshes the list.
func submitCreate(ctx context.Context, client sdk.Client, model *dashboardModel) {
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := client.Sandboxes().Create(callCtx, model.pendingCreate)
	if err != nil {
		model.notice = "create failed: " + err.Error()
		return
	}
	model.notice = "created " + model.pendingCreate.Name + " (stopped; start it from the list)"
}

// dashboardAction applies a lifecycle action to the selected sandbox.
func dashboardAction(ctx context.Context, client sdk.Client, model *dashboardModel, action string) {
	if len(model.items) == 0 {
		return
	}
	item := model.items[model.selected]
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var err error
	switch action {
	case "start":
		if item.State != sandboxStateStopped {
			model.notice = item.Name + " is not stopped"
			return
		}
		_, err = client.Sandboxes().Start(callCtx, item.ID)
	case "stop":
		if item.State != sandboxStateRunning {
			model.notice = item.Name + " is not running"
			return
		}
		_, err = client.Sandboxes().Stop(callCtx, item.ID, sdk.StopOptions{})
	case "rm":
		_, err = client.Sandboxes().Delete(callCtx, item.ID, sdk.DeleteOptions{Force: item.State == sandboxStateRunning})
	}
	if err != nil {
		model.notice = action + " failed: " + err.Error()
		return
	}
	model.notice = action + " " + item.Name
	refreshDashboard(ctx, client, model)
}
