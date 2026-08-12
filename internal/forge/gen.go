package forge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trustabl/trustabl/internal/models"
	"github.com/trustabl/trustabl/internal/rules"
)

// severityRank maps a severity string to a sort key (lower = higher priority).
func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	default:
		return 4
	}
}

// firstSentence returns s up to and including the first ". " boundary (or end
// of string). Normalizes internal whitespace. If maxLen > 0 and the result
// exceeds maxLen, the string is truncated with a Unicode ellipsis.
func firstSentence(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i+1]
	}
	if maxLen > 0 && len([]rune(s)) > maxLen {
		runes := []rune(s)
		cut := maxLen - 1
		for cut > 0 && runes[cut] != ' ' {
			cut--
		}
		if cut == 0 {
			cut = maxLen - 1
		}
		s = strings.TrimRight(string(runes[:cut]), " ") + "…"
	}
	return s
}

// matchCondition derives a human-readable "When this applies" string from a
// MatchExpr. Handles the all: combinator by joining sub-conditions. Falls back
// to a generic string when no recognized predicate is set.
func matchCondition(expr rules.MatchExpr) string {
	if len(expr.All) > 0 {
		var parts []string
		for _, sub := range expr.All {
			c := matchCondition(sub)
			if c != "" && c != "When the condition described by this rule is met." {
				parts = append(parts, strings.TrimSuffix(c, "."))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, ", and ") + "."
		}
	}
	switch {
	case expr.SkillAllowsUnrestrictedShell != nil:
		return "Every skill — always verify allowed-tools before emitting."
	case expr.SkillBodyHasDynamicExec != nil:
		return "Any skill body that uses the backtick-exec or fenced-exec form."
	case expr.SkillDynamicExecTouchesNetworkOrSecrets != nil:
		return "Any dynamic-context command performing network egress or accessing credentials."
	case expr.SkillReferencesExternalURL != nil:
		return "Any skill body that references an http(s) URL."
	case expr.SkillBodyHasInjectionMarker != nil:
		return "Any skill containing instruction-override phrasing, invisible Unicode, or encoded blobs."
	case len(expr.SkillAllowsTool) > 0:
		return "Any skill pre-approving Bash, Write, Edit, WebFetch, or NotebookEdit in allowed-tools."
	case expr.SkillModelInvocable != nil:
		return "Any skill where disable-model-invocation is not set to true."
	case expr.SkillBundledScriptNetworkEgress != nil:
		return "Any skill directory that bundles scripts making outbound network calls."
	case expr.SkillBundledScriptReadsSecrets != nil:
		return "Any skill directory that bundles scripts reading credentials or secrets."
	case expr.SkillBundledFileHasHardcodedSecret != nil:
		return "Any file bundled within the skill directory."
	case expr.SkillDescriptionToolMismatch != nil:
		return "Any skill whose description claims read-only but grants side-effecting tools."
	case expr.SkillHasDescription != nil:
		return "Every skill — description is required."
	case expr.SkillHasDuplicateToolRefs != nil:
		return "Any skill with duplicate entries in allowed-tools."
	case expr.SkillIsAgentSpecific != nil:
		return "Only when frontmatter includes a context: or agent: binding field."
	}
	return "When the condition described by this rule is met."
}

// sanitizeEmittedText neutralizes literal strings that would trigger skill safety
// detectors on the generated file. Rule explanations quote the dangerous patterns
// they guard against; we must emit safe equivalents so the output does not
// self-flag when scanned.
func sanitizeEmittedText(s string) string {
	// Break the inline-exec regex (requires !` adjacently) by inserting a space.
	s = strings.ReplaceAll(s, "!`", "! `")
	// Neutralize the canonical injection phrase matched by CSKILL-040.
	s = strings.ReplaceAll(s, "ignore previous instructions", "ignore-previous-instructions")
	return s
}

// Generate produces a pre-coding SKILL.md from a policy's skill-scoped rules.
// Only rules already filtered to scope==skill should be passed; Generate does
// not re-filter. Output is byte-stable: rules are sorted by severity rank
// (critical first), then by rule ID ascending within each rank.
func Generate(meta rules.PolicyMeta, skillRules []rules.RuleDef) string {
	sorted := make([]rules.RuleDef, len(skillRules))
	copy(sorted, skillRules)
	sort.Slice(sorted, func(i, j int) bool {
		ri := severityRank(sorted[i].Severity)
		rj := severityRank(sorted[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return sorted[i].ID < sorted[j].ID
	})

	name := strings.ReplaceAll(strings.ToLower(meta.ID), "_", "-")
	desc := firstSentence(meta.Description, 120)

	var b strings.Builder

	// --- Frontmatter ---
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "name: %s\n", name)
	fmt.Fprintf(&b, "description: >-\n  %s\n", desc)
	fmt.Fprintf(&b, "allowed-tools: Read\n")
	fmt.Fprintf(&b, "disable-model-invocation: false\n")
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "\n")

	// --- Header ---
	fmt.Fprintf(&b, "# Trustabl Pre-Coding: %s\n", meta.Name)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "Before writing any SKILL.md, you MUST apply every constraint below. Rules are\n")
	fmt.Fprintf(&b, "ordered by severity. A violation here will fire the corresponding finding\n")
	fmt.Fprintf(&b, "in post-build scan — prevent it now.\n")
	fmt.Fprintf(&b, "\n")

	// --- Decision tree (derived from CSKILL-001 + CSKILL-050) ---
	fmt.Fprintf(&b, "## Tool Grant Decision Tree\n")
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "1. Does this skill need shell commands?\n")
	fmt.Fprintf(&b, "   YES → specify exact prefixes: Bash(git status *) — never bare Bash or Bash(*)\n")
	fmt.Fprintf(&b, "   NO  → omit Bash entirely\n")
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "2. Does allowed-tools include any of: Bash / Write / Edit / WebFetch / NotebookEdit?\n")
	fmt.Fprintf(&b, "   YES → set disable-model-invocation: true\n")
	fmt.Fprintf(&b, "   NO  → disable-model-invocation may be false (read-only skills are safe to auto-invoke)\n")
	fmt.Fprintf(&b, "\n")

	// --- Per-rule constraint blocks ---
	for _, r := range sorted {
		fmt.Fprintf(&b, "---\n")
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "## [%s] %s\n", r.ID, r.Title)
		fmt.Fprintf(&b, "**Severity:** %s | **Confidence:** %.2f\n", string(r.Severity), r.Confidence)
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "**Directive:** %s\n", sanitizeEmittedText(firstSentence(r.Fix, 0)))
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "**Why:** %s\n", sanitizeEmittedText(firstSentence(r.Explanation, 0)))
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "**When this applies:** %s\n", sanitizeEmittedText(matchCondition(r.Match)))
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}
