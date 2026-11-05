package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

type fakeSecretScreen struct {
	tcell.Screen
	events chan tcell.Event
	finis  bool
}

func (s *fakeSecretScreen) Init() error { return nil }
func (s *fakeSecretScreen) Fini()       { s.finis = true }
func (s *fakeSecretScreen) Size() (int, int) {
	return 80, 24
}
func (s *fakeSecretScreen) Clear()                                         {}
func (s *fakeSecretScreen) SetContent(int, int, rune, []rune, tcell.Style) {}
func (s *fakeSecretScreen) PutStrStyled(int, int, string, tcell.Style)     {}
func (s *fakeSecretScreen) Show()                                          {}
func (s *fakeSecretScreen) Sync()                                          {}
func (s *fakeSecretScreen) EventQ() chan tcell.Event                       { return s.events }

func TestBuildSecretRemovalChoicesIncludesSupportedCredentialTypes(t *testing.T) {
	inventory := secretRemovalInventory{
		services: []sdk.ServiceSecret{
			{Service: "openai", Scope: sdk.SecretScopeGlobal},
			{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
		},
		registries: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
			{Registry: "private.example", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
		},
		accounts: []string{"docker"},
	}
	choices := buildSecretRemovalChoices(inventory, "", false)
	if len(choices) != 5 {
		t.Fatalf("choice count=%d choices=%+v", len(choices), choices)
	}
	choices = buildSecretRemovalChoices(inventory, "dev", false)
	if len(choices) != 2 {
		t.Fatalf("sandbox-filtered choice count=%d choices=%+v", len(choices), choices)
	}
	for _, choice := range choices {
		if choice.sandbox != "dev" || choice.provider != "" {
			t.Fatalf("sandbox filter included an unrelated choice: %+v", choice)
		}
	}
	choices = buildSecretRemovalChoices(inventory, "", true)
	if len(choices) != 3 {
		t.Fatalf("global-filtered choice count=%d choices=%+v", len(choices), choices)
	}
	for _, choice := range choices {
		if choice.scope == sdk.SecretScopeSandbox || choice.regScope == sdk.RegistryScopeSandbox {
			t.Fatalf("global filter included sandbox credential: %+v", choice)
		}
	}
}

func TestSecretSelectorSanitizesTerminalControlAndDirectionOverrides(t *testing.T) {
	got := sanitizeTerminalText("private\x1b[31m\u202e.example")
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("unsafe terminal control survived sanitization: %q", got)
	}
}

func TestSecretSelectionArrowEnterAndCancelEvents(t *testing.T) {
	selected := 0
	selected, done, accept := updateSecretSelection(tcell.NewEventKey(tcell.KeyDown, "", tcell.ModNone), selected, 2)
	if selected != 1 || done || accept {
		t.Fatalf("down event=(%d,%t,%t)", selected, done, accept)
	}
	selected, done, accept = updateSecretSelection(tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone), selected, 2)
	if selected != 1 || !done || !accept {
		t.Fatalf("enter event=(%d,%t,%t)", selected, done, accept)
	}
	_, done, accept = updateSecretSelection(tcell.NewEventKey(tcell.KeyRune, "q", tcell.ModNone), selected, 2)
	if !done || accept {
		t.Fatalf("cancel event=(%t,%t)", done, accept)
	}
}

func TestTcellSelectorReturnsArrowSelectedIndex(t *testing.T) {
	screen := &fakeSecretScreen{events: make(chan tcell.Event, 2)}
	screen.events <- tcell.NewEventKey(tcell.KeyDown, "", tcell.ModNone)
	screen.events <- tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone)
	selected, err := selectSecretRemovalChoice(screen, []secretRemovalChoice{{label: "first"}, {label: "second"}})
	if err != nil || selected != 1 {
		t.Fatalf("selected=%d err=%v", selected, err)
	}
}

func TestTcellSelectorCancelFinalizesScreen(t *testing.T) {
	screen := &fakeSecretScreen{events: make(chan tcell.Event, 1)}
	screen.events <- tcell.NewEventKey(tcell.KeyEscape, "", tcell.ModNone)
	selected, err := selectSecretService(screen, []string{"openai"})
	if err != nil || selected != "" {
		t.Fatalf("selected=%q err=%v", selected, err)
	}
	if !screen.finis {
		t.Fatal("cancel path did not finalize the terminal screen")
	}
}

func TestSecretRemoveWithoutNameUsesInteractiveSelector(t *testing.T) {
	secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{
		{Service: "openai", Scope: sdk.SecretScopeGlobal},
		{Service: "github", Scope: sdk.SecretScopeGlobal},
	}}
	client := fakeClient{secrets: secrets, registry: &fakeRegistryCredentials{}, accounts: fakeAccounts{}}
	screen := &fakeSecretScreen{events: make(chan tcell.Event, 2)}
	screen.events <- tcell.NewEventKey(tcell.KeyDown, "", tcell.ModNone)
	screen.events <- tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone)
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""),
		NewClient:    func(string) (sdk.Client, error) { return client, nil },
		SecretScreen: func() tcell.Screen { return screen },
	}
	if code := runner.Run(context.Background(), []string{"secret", "rm"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(secrets.removed) != 1 || secrets.removed[0].Service != "openai" {
		t.Fatalf("selected removal=%+v choices=%+v output=%q", secrets.removed, buildSecretRemovalChoices(secretRemovalInventory{services: secrets.items}, "", false), out.String())
	}
	if !screen.finis {
		t.Fatal("selector did not finalize the terminal screen")
	}
}

func TestSecretSetWithoutServiceUsesInteractiveSelector(t *testing.T) {
	secrets := &fakeServiceSecrets{}
	client := fakeClient{secrets: secrets}
	screen := &fakeSecretScreen{events: make(chan tcell.Event, 6)}
	for range 5 {
		screen.events <- tcell.NewEventKey(tcell.KeyDown, "", tcell.ModNone)
	}
	screen.events <- tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone)
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""),
		NewClient:    func(string) (sdk.Client, error) { return client, nil },
		SecretScreen: func() tcell.Screen { return screen },
	}
	if code := runner.Run(context.Background(), []string{"secret", "set", "--token", "synthetic-token"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if secrets.service != "github" || string(secrets.value) != "synthetic-token" {
		t.Fatalf("stored service=%q value=%q output=%q", secrets.service, secrets.value, out.String())
	}
	if !screen.finis {
		t.Fatal("selector did not finalize the terminal screen")
	}
}
