package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trustabl/trustabl/internal/forge"
	"github.com/trustabl/trustabl/internal/models"
	"github.com/trustabl/trustabl/internal/rules"
	"github.com/trustabl/trustabl/internal/rulesource"
	"github.com/trustabl/trustabl/internal/telemetry"
)

func newForgeCommand(tel *telemetry.Client) *cobra.Command {
	var policy, output, rulesRef string

	cmd := &cobra.Command{
		Use:   "forge",
		Short: "Generate a pre-coding reliability skill from a Trustabl policy",
		Long: `Generate a pre-coding SKILL.md from a Trustabl detection policy pack.

The generated skill embeds the policy's rules as imperative constraints that an
AI model follows when authoring agent code — catching reliability and safety
issues before they are written rather than after scanning. It is the pre-coding
counterpart to "trustabl scan":

  trustabl scan    — analyze what was built
  trustabl forge   — generate what should be built right

The output is a SKILL.md written to stdout (or --output) that can be injected
into an AI model's context alongside the user's prompt before code generation.

Rules are resolved from the trustabl-rules repository (same source as
"trustabl scan"). Pass --rules-ref to pin a specific branch or tag.`,
		Example: `  # Generate a pre-coding skill for Claude Code skill authoring
  trustabl forge --policy claude_skill

  # Write directly to a file
  trustabl forge --policy claude_skill --output pre-coding-skill.md

  # Pin the rules branch
  trustabl forge --policy claude_skill --rules-ref v1.2.0`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tel != nil {
				tel.Track("command.run", map[string]any{
					"command": "forge",
					"policy":  policy,
				})
			}
			return runForge(cmd, policy, output, rulesRef)
		},
	}

	cmd.Flags().StringVar(&policy, "policy", "",
		"policy category to generate from (e.g. claude_skill) [required]")
	_ = cmd.MarkFlagRequired("policy")
	cmd.Flags().StringVarP(&output, "output", "o", "",
		"write the generated SKILL.md to this path (default: stdout)")
	cmd.Flags().StringVar(&rulesRef, "rules-ref", "",
		"pin the trustabl-rules branch or tag (default: latest cached)")

	return cmd
}

func runForge(cmd *cobra.Command, policy, output, rulesRef string) error {
	if !models.ValidCategory(models.DetectorCategory(policy)) {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"trustabl forge: unknown policy category %q; accepted values: %v\n",
			policy, models.AllCategories)
		return exitCodeError{code: 1}
	}

	res, err := rulesource.Resolve(
		rulesource.Config{Ref: rulesRef},
		rules.SupportedSchemaVersion,
	)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "trustabl forge: rules: %v\n", err)
		return exitCodeError{code: 2}
	}

	policies, _, err := rules.LoadLenient(res.FS)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "trustabl forge: load rules: %v\n", err)
		return exitCodeError{code: 2}
	}

	var meta rules.PolicyMeta
	var skillRules []rules.RuleDef
	for _, pf := range policies {
		if pf.Policy.Category != models.DetectorCategory(policy) {
			continue
		}
		meta = pf.Policy
		for _, r := range pf.Rules {
			if r.Scope == models.ScopeSkill {
				skillRules = append(skillRules, r)
			}
		}
	}

	if len(skillRules) == 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"trustabl forge: no skill-scoped rules found in policy %q\n", policy)
		return nil
	}

	content := forge.Generate(meta, skillRules)

	if output == "" {
		fmt.Fprint(cmd.OutOrStdout(), content)
		return nil
	}
	return os.WriteFile(output, []byte(content), 0o644)
}
