package command

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"golang.org/x/term"
)

var serviceEnvVars = map[string][]string{
	"anthropic":   {"ANTHROPIC_API_KEY"},
	"copilot":     {"COPILOT_API_KEY"},
	"cursor":      {"CURSOR_API_KEY"},
	"devin":       {"DEVIN_API_KEY"},
	"droid":       {"DROID_API_KEY"},
	"github":      {"GH_TOKEN", "GITHUB_TOKEN"},
	"google":      {"GOOGLE_API_KEY", "GEMINI_API_KEY"},
	"groq":        {"GROQ_API_KEY"},
	"mistral":     {"MISTRAL_API_KEY"},
	"nebius":      {"NEBIUS_API_KEY"},
	openAIService: {openAIAPIKeyEnv},
	"openrouter":  {"OPENROUTER_API_KEY"},
	"xai":         {"XAI_API_KEY"},
}

func (r *Runner) secretImportHelp() int {
	const usage = `Description:
  Import supported service secrets detected in host environment variables.
  Available services: anthropic, copilot, cursor, devin, droid, github, google,
  groq, mistral, nebius, openai, openrouter, xai.

  Existing global entries require confirmation before overwrite. Each detected
  value shows a last-four-character preview and prompts with a default of yes
  unless --all or --force is passed. --all imports new entries and skips existing
  ones; --force imports without prompting and overwrites existing entries.
  A stored OpenAI OAuth session takes precedence over OPENAI_API_KEY.
  --dry-run never writes and shows only a last-four-character preview.

Usage:
  rsbx secret import [SERVICE] [flags]

Examples:
  rsbx secret import
  rsbx secret import github
  rsbx secret import --all
  rsbx secret import github --force
  rsbx secret import --dry-run

Flags:
      --all       Import every detected variable without prompting
      --dry-run   Show what would be imported without writing
  -f, --force     Overwrite an existing stored entry
  -h, --help      Show this help
`
	if _, err := io.WriteString(r.Out, usage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

//nolint:gocognit,gocyclo,cyclop,funlen // interactive import intentionally handles each branch explicitly.
func (r *Runner) serviceSecretImport(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, nil)
	fs := flag.NewFlagSet("secret import", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	all := fs.Bool("all", false, "import every detected variable without prompting")
	force := fs.Bool("force", false, "overwrite existing secrets")
	fs.BoolVar(force, "f", false, "overwrite existing secrets")
	dryRun := fs.Bool("dry-run", false, "show what would be imported")
	if code, done := r.parseFlagsOrFail("secret import", fs, args); done {
		return code
	}
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret import [SERVICE] [--all] [--force] [--dry-run]")
		return 2
	}
	requested := ""
	if fs.NArg() == 1 {
		requested = strings.ToLower(fs.Arg(0))
		if !validServiceSecret(requested) {
			r.error(fmt.Errorf("unknown service %q", requested))
			return 2
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	secretStore := sdk.Secrets(client)
	existing := make(map[string]bool)
	if !*force {
		items, err := secretStore.List(ctx)
		if err != nil {
			r.error(fmt.Errorf("list stored secrets before import: %w", err))
			return 1
		}
		for _, item := range items {
			if item.Scope == sdk.SecretScopeGlobal {
				existing[item.Service] = true
			}
		}
	}
	oauthPresent := false
	if requested == "" || requested == openAIService {
		if _, value := lookupServiceEnv(openAIService); value != "" {
			present, err := sdk.AccountStatus(client).Status(ctx, openAIService)
			if err != nil {
				r.error(fmt.Errorf("check %s OAuth credentials before import: %w", openAIService, err))
				return 1
			}
			oauthPresent = present
		}
	}
	imported := 0
	skipped := 0
	detected := false
	input := bufio.NewReader(r.In)
	for _, service := range serviceSecretNames {
		if requested != "" && service != requested {
			continue
		}
		name, value := lookupServiceEnv(service)
		if name == "" {
			continue
		}
		detected = true
		if service == openAIService && oauthPresent {
			_, _ = fmt.Fprintf(r.Err, "skip %s: OAuth credentials are already stored and take precedence\n", service)
			skipped++
			continue
		}
		if *dryRun {
			switch {
			case existing[service] && *all && !*force:
				_, _ = fmt.Fprintf(r.Out, "Would skip %s from %s: already stored (last 4: %s)\n", service, name, lastFourPreview(value))
			case existing[service]:
				_, _ = fmt.Fprintf(r.Out, "Would overwrite %s from %s (last 4: %s)\n", service, name, lastFourPreview(value))
			default:
				_, _ = fmt.Fprintf(r.Out, "Would import %s from %s (last 4: %s)\n", service, name, lastFourPreview(value))
			}
			continue
		}
		if existing[service] && *all && !*force {
			_, _ = fmt.Fprintf(r.Err, "skip %s: already stored (use --force to replace it)\n", service)
			skipped++
			continue
		}
		if !*all && !*force {
			ok, err := r.confirmSecretImport(input, service, name, value, existing[service])
			if err != nil {
				r.error(err)
				return 1
			}
			if !ok {
				skipped++
				continue
			}
		}
		var err error
		if *force || existing[service] {
			_, err = secretStore.Set(ctx, service, sdk.SecretScopeGlobal, "", []byte(value))
		} else {
			_, err = secretStore.Create(ctx, service, sdk.SecretScopeGlobal, "", []byte(value))
		}
		if err != nil {
			r.error(err)
			return 1
		}
		imported++
		_, _ = fmt.Fprintf(r.Out, "imported %s from %s\n", service, name)
	}
	if detected && !*dryRun {
		_, _ = fmt.Fprintf(r.Out, "  %d secrets imported · %d skipped\n", imported, skipped)
	}
	if !detected {
		if requested != "" {
			_, _ = fmt.Fprintf(r.Err, "No env var detected for %q on the host. Either the env var isn't set, or %q isn't a known credential service.\n", requested, requested)
		} else {
			_, _ = fmt.Fprintln(r.Err, "No credential env vars detected on the host. Set e.g. OPENAI_API_KEY in your shell and re-run, or use `rsbx secret set` to enter a value directly.")
		}
	}
	return 0
}

func lookupServiceEnv(service string) (string, string) {
	for _, name := range serviceEnvVars[service] {
		if value := os.Getenv(name); value != "" {
			return name, value
		}
	}
	return "", ""
}

func (r *Runner) confirmSecretImport(input *bufio.Reader, service, name, value string, overwrite bool) (bool, error) {
	action := "Import"
	if overwrite {
		action = "Overwrite"
	}
	if _, err := fmt.Fprintf(r.Err, "%s %s from %s (last 4: %s) into the global keychain? (Y/n) ", action, service, name, lastFourPreview(value)); err != nil {
		return false, err
	}
	line, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if !isTerminalReader(input) {
		if _, writeErr := fmt.Fprintln(r.Err); writeErr != nil {
			return false, writeErr
		}
	}
	if errors.Is(err, io.EOF) && line == "" {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		return true, nil
	}
	return answer == answerShortYes || answer == answerYes, nil
}

func isTerminalReader(input io.Reader) bool {
	file, ok := input.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func lastFourPreview(value string) string {
	runes := []rune(value)
	if len(runes) <= 4 {
		return strings.Repeat("•", len(runes))
	}
	return string(runes[len(runes)-4:])
}
