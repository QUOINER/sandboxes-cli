package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// egressDecision mirrors the gateway audit record (gvproxy-egress-policy-v2
// EgressDecision). It carries no headers, payloads, or credentials.
type egressDecision struct {
	Time        string `json:"time"`
	SandboxID   string `json:"sandboxId,omitempty"`
	Revision    string `json:"revision"`
	Protocol    string `json:"protocol"`
	Destination string `json:"destination"`
	Port        uint16 `json:"port"`
	Action      string `json:"action"`
	Reason      string `json:"reason,omitempty"`
	Rule        string `json:"rule,omitempty"`
}

const policyLogUsage = "usage: rsbx policy log [SANDBOX] [--type all|network] [--limit N] [--format table|json|yaml]"

// policyLog prints gateway audit decisions from the host run directory.
func (r *Runner) policyLog(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true, limitFlag: true, "--type": true})
	fs := flag.NewFlagSet("policy log", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	limit := fs.Int(limitFlag[2:], 0, "maximum number of log entries to show (0 = all)")
	logType := fs.String("type", "all", "filter logs by type: all or network")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy log", err)
	}
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, policyLogUsage)
		return 2
	}
	if *logType != "all" && *logType != networkKeyword {
		r.error(fmt.Errorf("unsupported log type %q; filesystem logs are not supported", *logType))
		return 2
	}
	if *limit < 0 {
		r.error(errors.New("limit must be non-negative"))
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	decisions, malformed, err := r.readAuditDecisions(ctx, fs.Args())
	if err != nil {
		r.error(err)
		return 1
	}
	if *limit > 0 && len(decisions) > *limit {
		decisions = decisions[len(decisions)-*limit:]
	}
	return r.renderPolicyLog(selected, decisions, malformed)
}

// readAuditDecisions reads every <sandbox>.audit.jsonl in the daemon run
// directory, optionally restricted to one sandbox name.
func (r *Runner) readAuditDecisions(_ context.Context, filter []string) ([]egressDecision, int, error) {
	runDir := filepath.Join(diagnoseStateDir(r.Socket), "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, 0, fmt.Errorf("read policy log directory: %w", err)
	}
	nameFilter := ""
	if len(filter) == 1 {
		nameFilter = filter[0]
	}
	var decisions []egressDecision
	malformed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".audit.jsonl") {
			continue
		}
		sandbox := strings.TrimSuffix(entry.Name(), ".audit.jsonl")
		if nameFilter != "" && sandbox != nameFilter {
			continue
		}
		file, err := os.Open(filepath.Join(runDir, entry.Name())) // #nosec G304 -- audit files live in the daemon run directory.
		if err != nil {
			return nil, 0, fmt.Errorf("open policy log: %w", err)
		}
		parsed, bad := parseAuditFile(file, sandbox)
		_ = file.Close()
		decisions = append(decisions, parsed...)
		malformed += bad
	}
	sort.SliceStable(decisions, func(i, j int) bool {
		return decisions[i].Time < decisions[j].Time
	})
	return decisions, malformed, nil
}

func parseAuditFile(reader io.Reader, fallbackSandbox string) ([]egressDecision, int) {
	var decisions []egressDecision
	malformed := 0
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var decision egressDecision
		if err := json.Unmarshal([]byte(line), &decision); err != nil || decision.Time == "" || decision.Action == "" {
			malformed++
			continue
		}
		if decision.SandboxID == "" {
			decision.SandboxID = fallbackSandbox
		}
		decisions = append(decisions, decision)
	}
	return decisions, malformed
}

func (r *Runner) renderPolicyLogTable(decisions []egressDecision, malformed int) int {
	if len(decisions) == 0 {
		_, _ = fmt.Fprintln(r.Out, "No policy log entries")
	} else {
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TIME\tSANDBOX\tPROTOCOL\tDESTINATION\tPORT\tACTION\tREASON\tRULE")
		for i := range decisions {
			decision := &decisions[i]
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
				decision.Time, decision.SandboxID, decision.Protocol, decision.Destination,
				decision.Port, decision.Action, decision.Reason, decision.Rule)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
	}
	if malformed > 0 {
		_, _ = fmt.Fprintf(r.Out, "(%d malformed entries skipped)\n", malformed)
	}
	return 0
}

func (r *Runner) renderPolicyLog(format string, decisions []egressDecision, malformed int) int {
	if format == listFormatTable {
		return r.renderPolicyLogTable(decisions, malformed)
	}
	payload := struct {
		Decisions []egressDecision `json:"decisions" yaml:"decisions"`
		Malformed int              `json:"malformed" yaml:"malformed"`
	}{Decisions: decisions, Malformed: malformed}
	if format == listFormatYAML {
		data, err := yaml.Marshal(payload)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	}
	encoder := json.NewEncoder(r.Out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

// policyInspect shows full detail for one rule (by rule ID) or one sandbox's
// policy (by sandbox name), including the exact removal command.
func (r *Runner) policyInspect(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := flag.NewFlagSet("policy inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy inspect RULE_ID|SANDBOX [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	selector := fs.Arg(0)
	if rules, found := r.inspectRuleByID(ctx, client, selector); found {
		if err := renderPolicyRules(r.Out, selected, rules); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	id, err := findExecSandbox(ctx, client, selector)
	if err != nil {
		r.error(fmt.Errorf("no policy or rule matches %q", selector))
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	if err := renderPolicyRules(r.Out, selected, policyRules(sb)); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

// inspectRuleByID matches a selector against global and every sandbox's rule
// IDs and returns the matching rules.
func (r *Runner) inspectRuleByID(ctx context.Context, client sdk.Client, selector string) ([]policyRuleOutput, bool) {
	globalAllow, globalDeny, err := globalPolicyForList(ctx, client)
	if err != nil {
		return nil, false
	}
	globalRules := policyRulesFrom("global", globalAllow, globalDeny)
	for i := range globalRules {
		if globalRules[i].RuleID == selector {
			return []policyRuleOutput{globalRules[i]}, true
		}
	}
	page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 500})
	if err != nil {
		return nil, false
	}
	for i := range page.Items {
		rules := policyRules(&page.Items[i])
		for j := range rules {
			if rules[j].RuleID == selector {
				return []policyRuleOutput{rules[j]}, true
			}
		}
	}
	return nil, false
}
