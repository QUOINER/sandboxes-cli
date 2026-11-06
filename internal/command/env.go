package command

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rheic/sandboxes-cli/internal/envfile"
)

func (r *Runner) environment(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprint(r.Out, "Usage: rsbx env plan [PATH...]\n\nCreate a static, read-only preview from the current directory and optional user defaults, or from explicit sbxenv.yaml paths. Explicit paths skip user defaults.\nNo sandbox is created or changed; environment values are never displayed.\nApply, create, run, exec, and rm are unsupported.\n")
		return 0
	}
	if args[0] != "plan" {
		_, _ = fmt.Fprintf(r.Err, "rsbx env %s: unsupported: only static plan preview is implemented\n", args[0])
		return 1
	}
	fs := flag.NewFlagSet("env plan", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	name := fs.String("name", "", "override the environment sandbox name")
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), "Usage: rsbx env plan [PATH...] [flags]\n\nWithout PATH, read sbxenv.yaml from the current directory and merge optional ~/.sbxenv.yaml defaults first. Explicit file or directory paths merge in order and skip user defaults.\n  --name NAME  override the sandbox name\n\nThis is a static preview only; it does not apply changes or inspect daemon state.\n")
	}
	if err := fs.Parse(reorderFlagArgs(args[1:], map[string]bool{"--name": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env plan", err)
	}
	plan, err := loadEnvironmentPlan(fs.Args())
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	if err := applyEnvironmentName(&plan, *name); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	var out strings.Builder
	fmt.Fprintln(&out, "Static preview (no changes applied; daemon state not queried)")
	fmt.Fprintf(&out, "Name: %s\nAgent: %s\n", displayValue(plan.Name), plan.Agent)
	fmt.Fprintf(&out, "Workspace: %s\n", displayPath(plan.Workspace))
	fmt.Fprintf(&out, "Additional workspaces: %d\n", len(plan.AdditionalWorkspaces))
	for _, workspace := range plan.AdditionalWorkspaces {
		mode := "read-write"
		if workspace.ReadOnly {
			mode = "read-only"
		}
		fmt.Fprintf(&out, "  %q (%s)\n", workspace.Path, mode)
	}
	fmt.Fprintf(&out, "Environment keys: %d\n", len(plan.EnvironmentKeys))
	for _, key := range plan.EnvironmentKeys {
		fmt.Fprintf(&out, "  %s=<redacted>\n", key)
	}
	if plan.CPUs != nil {
		fmt.Fprintf(&out, "CPUs: %d\n", *plan.CPUs)
	}
	if plan.Memory != "" {
		fmt.Fprintf(&out, "Memory: %s\n", plan.Memory)
	}
	if _, err := fmt.Fprint(r.Out, out.String()); err != nil {
		r.error(errors.New("write environment plan failed"))
		return 1
	}
	return 0
}

func applyEnvironmentName(plan *envfile.Plan, name string) error {
	if name == "" {
		return nil
	}
	if err := envfile.ValidateName(name); err != nil {
		return err
	}
	plan.Name = name
	return nil
}

func loadEnvironmentPlan(paths []string) (envfile.Plan, error) {
	if len(paths) > 0 {
		return envfile.Load(paths)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	return envfile.LoadDefault(homeDir, workingDir)
}

func displayValue(value string) string {
	if value == "" {
		return "(unset)"
	}
	return value
}

func displayPath(value string) string {
	if value == "" {
		return "(unset)"
	}
	return fmt.Sprintf("%q", value)
}
