package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/kit"
)

const kitUsage = `Usage: rsbx kit COMMAND

Manage local Rheic kits, the supported Docker Kits v2 sandbox subset and
Docker kit v3 descriptors (offline inspection only; no kit builder is
implemented). Kits are unsigned local inputs; remote OCI kits, mixins,
signatures and MCP allowlists are not implemented yet.

Commands:
  inspect FILE_OR_DIR [--format table|json|yaml]   validate and print a kit
  ls [DIR]                                  list local .yaml kits
`

func (r *Runner) kit(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, kitUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, kitUsage)
		return 0
	case commandInspect:
		return r.kitInspect(args[1:])
	case "ls", commandList:
		return r.kitList(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx kit: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (r *Runner) kitInspect(args []string) int {
	fs := flag.NewFlagSet("kit inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(moveKitInspectFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("kit inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx kit inspect FILE_OR_DIR [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	doc, err := kit.Load(fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	if doc.V3 != nil {
		return r.printV3Kit(doc.V3, selected)
	}
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tAGENT\tIMAGE\tPROFILE\tMOUNTS")
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", doc.Metadata.Name, doc.Spec.Agent, doc.Spec.Image, doc.Spec.PolicyProfile, strings.Join(doc.Paths(), ","))
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(doc)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) printV3Kit(doc *kit.V3Descriptor, selected string) int {
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "KIND\tNAME\tVERSION\tCAPABILITIES")
		label := doc.DisplayName
		if label == "" {
			label = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", doc.Kind, label, doc.Version, len(doc.Capabilities))
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(doc)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func moveKitInspectFlags(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		if arg == formatFlag || arg == "-format" {
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, positionals...)
}

func (r *Runner) kitList(args []string) int {
	if len(args) > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx kit ls [DIR]")
		return 2
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.error(err)
		return 1
	}
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FILE\tNAME\tAGENT\tPROFILE")
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		doc, err := kit.Load(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		found++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", entry.Name(), doc.Metadata.Name, doc.Spec.Agent, doc.Spec.PolicyProfile)
	}
	if err := tw.Flush(); err != nil {
		r.error(err)
		return 1
	}
	if found == 0 {
		_, _ = fmt.Fprintln(r.Out, "No local kits found")
	}
	return 0
}

func applyKit(ctx context.Context, path string, agent, image, profile *string, paths, env *[]string, oauthCredentials *[]sdk.OAuthCredential) error {
	doc, err := kit.Load(path)
	if err != nil {
		return err
	}
	if doc.V3 != nil {
		return errors.New("kit v3 descriptors require a kit builder; building and applying v3 kits is not implemented")
	}
	for _, value := range []struct {
		label   string
		target  *string
		fromKit string
	}{
		{"agent", agent, doc.Spec.Agent}, {"image", image, doc.Spec.Image}, {"policy profile", profile, doc.Spec.PolicyProfile},
	} {
		if err := mergeKitValue(value.label, value.target, value.fromKit); err != nil {
			return err
		}
	}
	if seed := doc.Spec.Workspace.Seed; seed != "" {
		resolved, err := kit.ResolveSeed(ctx, seed, kit.SeedCacheRoot())
		if err != nil {
			return err
		}
		*paths = append([]string{resolved}, *paths...)
	}
	*paths = append(*paths, doc.Paths()...)
	converted, err := convertOAuthCredentials(doc.Spec.Credentials)
	if err != nil {
		return err
	}
	*oauthCredentials = append(*oauthCredentials, converted...)
	return mergeOAuthEnvironment(doc, env)
}

func mergeKitValue(label string, target *string, fromKit string) error {
	if *target != "" && fromKit != "" && *target != fromKit {
		return fmt.Errorf("kit %s %q conflicts with requested %q", label, fromKit, *target)
	}
	if *target == "" {
		*target = fromKit
	}
	return nil
}

func convertOAuthCredentials(credentials []kit.Credential) ([]sdk.OAuthCredential, error) {
	converted := make([]sdk.OAuthCredential, 0, len(credentials))
	for _, credential := range credentials {
		oauth := credential.OAuth
		if oauth == nil {
			continue
		}
		// OpenAI OAuth uses the daemon's separately configured provider adapter;
		// this declaration cannot replace its issuer or endpoint policy.
		if credential.Service == openAIService {
			continue
		}
		var tokenEndpoint *sdk.OAuthTokenEndpoint
		if oauth.TokenEndpoint != nil {
			tokenEndpoint = &sdk.OAuthTokenEndpoint{Host: oauth.TokenEndpoint.Host, Path: oauth.TokenEndpoint.Path}
		}
		var sentinels *sdk.OAuthSentinels
		if oauth.Sentinels != nil {
			sentinels = &sdk.OAuthSentinels{AccessToken: oauth.Sentinels.AccessToken, RefreshToken: oauth.Sentinels.RefreshToken}
		}
		var credentialFile *sdk.OAuthCredentialFile
		if oauth.CredentialFile != nil {
			structure := ""
			if len(oauth.CredentialFile.Structure) > 0 {
				encoded, err := json.Marshal(oauth.CredentialFile.Structure)
				if err != nil {
					return nil, fmt.Errorf("encode kit OAuth credential structure: %w", err)
				}
				structure = string(encoded)
			}
			credentialFile = &sdk.OAuthCredentialFile{Path: oauth.CredentialFile.Path, StructureJSON: structure, Template: oauth.CredentialFile.Template}
		}
		var responseFields *sdk.OAuthResponseFields
		if oauth.ResponseFields != nil {
			fields := oauth.ResponseFields
			responseFields = &sdk.OAuthResponseFields{AccessToken: fields.AccessToken, RefreshToken: fields.RefreshToken, ExpiresIn: fields.ExpiresIn, Scope: fields.Scope, IDToken: fields.IDToken}
		}
		converted = append(converted, sdk.OAuthCredential{Service: credential.Service,
			TokenEndpoint:  tokenEndpoint,
			ResourceHosts:  append([]string(nil), oauth.ResourceHosts...),
			Sentinels:      sentinels,
			CredentialFile: credentialFile,
			ResponseFields: responseFields,
			Passthrough:    oauth.Passthrough, SkipIfEnv: append([]string(nil), oauth.SkipIfEnv...)})
	}
	return converted, nil
}

func mergeOAuthEnvironment(doc kit.Kit, env *[]string) error {
	for _, credentialEnv := range doc.OAuthEnvironment() {
		credentialKey, _, _ := strings.Cut(credentialEnv, "=")
		baseURLKey := ""
		if credentialKey == openAIAPIKeyEnv {
			baseURLKey = openAIBaseURLEnv
		}
		for _, existing := range *env {
			key, _, _ := strings.Cut(existing, "=")
			if key == credentialKey || (baseURLKey != "" && key == baseURLKey) {
				return fmt.Errorf("kit OAuth credential conflicts with explicit %s", key)
			}
		}
		*env = append(*env, credentialEnv)
	}
	return nil
}
