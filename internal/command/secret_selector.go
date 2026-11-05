package command

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/gdamore/tcell/v3"
	"github.com/gdamore/tcell/v3/color"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

type secretRemovalChoice struct {
	label    string
	service  string
	scope    sdk.SecretScope
	sandbox  string
	registry string
	regScope sdk.RegistryCredentialScope
	provider string
}

func buildSecretRemovalChoices(inventory secretRemovalInventory, sandboxFilter string) []secretRemovalChoice {
	choices := make([]secretRemovalChoice, 0, inventory.count())
	for _, item := range inventory.services {
		if sandboxFilter != "" && (item.Scope != sdk.SecretScopeSandbox || item.SandboxName != sandboxFilter) {
			continue
		}
		label := item.Service + " service secret (" + string(item.Scope)
		if item.SandboxName != "" {
			label += " " + item.SandboxName
		}
		choices = append(choices, secretRemovalChoice{label: sanitizeTerminalText(label + ")"), service: item.Service, scope: item.Scope, sandbox: item.SandboxName})
	}
	for _, item := range inventory.registries {
		if sandboxFilter != "" && (item.Scope != string(sdk.RegistryScopeSandbox) || item.SandboxName != sandboxFilter) {
			continue
		}
		label := item.Registry + " registry credential (" + item.Scope
		if item.SandboxName != "" {
			label += " " + item.SandboxName
		}
		choices = append(choices, secretRemovalChoice{label: sanitizeTerminalText(label + ")"), registry: item.Registry, regScope: sdk.RegistryCredentialScope(item.Scope), sandbox: item.SandboxName})
	}
	if sandboxFilter == "" {
		for _, provider := range inventory.accounts {
			choices = append(choices, secretRemovalChoice{label: provider + " account credentials", provider: provider})
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].label < choices[j].label })
	return choices
}

func selectSecretRemovalChoice(screen tcell.Screen, choices []secretRemovalChoice) (int, error) {
	labels := make([]string, len(choices))
	for index, choice := range choices {
		labels[index] = choice.label
	}
	return selectTerminalOption(screen, "Select credential: Up/Down move, Enter remove, q cancel", labels)
}

func selectSecretService(screen tcell.Screen, services []string) (string, error) {
	selected, err := selectTerminalOption(screen, "Select service: Up/Down move, Enter select, q cancel", services)
	if err != nil || selected < 0 || selected >= len(services) {
		return "", err
	}
	return services[selected], nil
}

func selectTerminalOption(screen tcell.Screen, heading string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, nil
	}
	if screen == nil {
		return -1, fmt.Errorf("interactive secret selection is unavailable")
	}
	if err := screen.Init(); err != nil {
		return -1, fmt.Errorf("initialize credential selector: %w", err)
	}
	defer screen.Fini()
	selected := 0
	offset := 0
	for {
		drawTerminalOptions(screen, heading, options, selected, &offset)
		event := <-screen.EventQ()
		switch event := event.(type) {
		case nil:
			return -1, nil
		case *tcell.EventResize:
			screen.Sync()
		case *tcell.EventKey:
			next, done, accept := updateSecretSelection(event, selected, len(options)-1)
			selected = next
			if done {
				if accept {
					return selected, nil
				}
				return -1, nil
			}
		}
	}
}

func updateSecretSelection(event *tcell.EventKey, selected, last int) (int, bool, bool) {
	if event == nil {
		return selected, false, false
	}
	switch event.Key() {
	case tcell.KeyUp:
		if selected > 0 {
			selected--
		}
	case tcell.KeyDown:
		if selected < last {
			selected++
		}
	case tcell.KeyEnter:
		return selected, true, true
	case tcell.KeyEscape, tcell.KeyCtrlC:
		return selected, true, false
	case tcell.KeyRune:
		if event.Str() == "q" || event.Str() == "Q" {
			return selected, true, false
		}
	}
	return selected, false, false
}

func drawTerminalOptions(screen tcell.Screen, heading string, options []string, selected int, offset *int) {
	width, height := screen.Size()
	if height < 1 {
		return
	}
	visible := height - 1
	if visible < 1 {
		visible = 1
	}
	if selected < *offset {
		*offset = selected
	} else if selected >= *offset+visible {
		*offset = selected - visible + 1
	}
	base := tcell.StyleDefault.Foreground(color.White).Background(tcell.ColorReset)
	highlight := base.Foreground(color.Black).Background(color.White)
	screen.Clear()
	drawSecretText(screen, 0, 0, width, heading, base)
	for row := 0; row < visible && *offset+row < len(options); row++ {
		style := base
		if *offset+row == selected {
			style = highlight
		}
		drawSecretText(screen, 0, row+1, width, sanitizeTerminalText(options[*offset+row]), style)
	}
	screen.Show()
}

func sanitizeTerminalText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return '�'
		}
		return character
	}, value)
}

func drawSecretText(screen tcell.Screen, x, y, width int, value string, style tcell.Style) {
	if width < 1 {
		return
	}
	screen.PutStrStyled(x, y, value, style)
}
