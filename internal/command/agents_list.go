package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

const agentsUsage = `usage: rsbx agents [ls|list] [--format table|json|yaml]

List built-in agents and their image, launch command, status, and authentication notes.
Preview agents can be launched, but have not passed full live-VM and authentication validation.
`

func (r *Runner) agents(args []string) int {
	if len(args) > 0 && (args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag) {
		_, _ = fmt.Fprint(r.Out, agentsUsage)
		return 0
	}
	if len(args) > 0 && args[0] != "ls" && args[0] != commandList {
		_, _ = fmt.Fprintf(r.Err, "rsbx agents: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, agentsUsage)
		return 2
	}
	if len(args) > 0 {
		args = args[1:]
	}
	return r.agentList(args)
}

func (r *Runner) agentList(args []string) int {
	fs := flag.NewFlagSet(commandAgents, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, agentsUsage)
			return 0
		}
		return r.flagParseFailure(commandAgents, err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, agentsUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	rows, err := templateRows()
	if err != nil {
		r.error(err)
		return 1
	}
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 3, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tSTATUS\tIMAGE\tCOMMAND\tAUTH")
		for _, row := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.Name, row.Status, row.Image, row.Command, row.Auth)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(rows)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rows); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}
