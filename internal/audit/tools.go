package audit

import (
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunToolsAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	for _, pathValue := range config.CollectKeyValues(loaded.Data, "elevated") {
		if enabled, ok := config.AsBool(pathValue.Value); ok && enabled {
			findings = append(findings, newFinding(
				"tools.elevated_enabled",
				"Elevated tool configuration is enabled",
				"tools",
				types.SeverityHigh,
				"An elevated tool configuration was detected, which can expand the blast radius of prompt injection or agent misuse.",
				[]string{pathEvidence(pathValue.Path, "elevated=true")},
				[]string{
					"Review whether elevated tool access is required.",
					"Limit elevated tools to the smallest trusted scope possible.",
				},
			))
			break
		}
		if nonEmpty(pathValue.Value) {
			findings = append(findings, newFinding(
				"tools.elevated_profile_present",
				"Elevated tool profile requires manual review",
				"tools",
				types.SeverityMedium,
				"A non-empty elevated tool configuration was detected and should be reviewed for blast radius.",
				[]string{pathEvidence(pathValue.Path, "non-empty elevated configuration")},
				[]string{
					"Document which commands or capabilities are elevated.",
					"Constrain elevated access to the minimum trusted workflow.",
				},
			))
			break
		}
	}

	for _, pathValue := range config.CollectKeyValues(loaded.Data, "sandbox") {
		if asString, ok := config.AsString(pathValue.Value); ok {
			normalized := strings.ToLower(strings.TrimSpace(asString))
			if normalized == "off" || normalized == "disabled" || normalized == "none" {
				findings = append(findings, newFinding(
					"tools.sandbox_disabled",
					"Sandbox appears disabled",
					"tools",
					types.SeverityMedium,
					"A sandbox setting indicates disabled or no sandbox isolation.",
					[]string{pathEvidence(pathValue.Path, "sandbox="+normalized)},
					[]string{
						"Enable sandboxing for tool execution where supported.",
						"Review whether high-risk tools can run without isolation.",
					},
				))
				break
			}
		}
		if enabled, ok := config.AsBool(pathValue.Value); ok && !enabled {
			findings = append(findings, newFinding(
				"tools.sandbox_bool_disabled",
				"Sandbox is explicitly disabled",
				"tools",
				types.SeverityMedium,
				"A sandbox setting is explicitly disabled.",
				[]string{pathEvidence(pathValue.Path, "sandbox=false")},
				[]string{
					"Enable sandboxing for high-risk tool execution.",
				},
			))
			break
		}
	}

	for _, pathValue := range config.CollectKeyValues(loaded.Data, "profile") {
		if asString, ok := config.AsString(pathValue.Value); ok && strings.Contains(strings.ToLower(asString), "elevated") {
			findings = append(findings, newFinding(
				"tools.profile_elevated",
				"Tool profile appears elevated",
				"tools",
				types.SeverityMedium,
				"A profile value suggests elevated tool permissions.",
				[]string{pathEvidence(pathValue.Path, "profile="+asString)},
				[]string{
					"Verify the intended tool profile for this agent or workflow.",
					"Use the narrowest tool profile possible.",
				},
			))
			break
		}
	}

	return findings
}
