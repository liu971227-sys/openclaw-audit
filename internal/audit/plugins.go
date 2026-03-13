package audit

import (
	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunPluginsAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	for _, key := range []string{"plugins", "extensions"} {
		for _, pathValue := range config.CollectKeyValues(loaded.Data, key) {
			if !nonEmpty(pathValue.Value) {
				continue
			}
			findings = append(findings, newFinding(
				"plugins.third_party_present",
				"Plugins or extensions require trust review",
				"plugins",
				types.SeverityMedium,
				"OpenClaw appears to load plugins or extensions, which should be reviewed for source trust and blast radius.",
				[]string{pathEvidence(pathValue.Path, key+" configured")},
				[]string{
					"Review plugin source trust and update cadence.",
					"Disable plugins that are not required for production use.",
				},
			))
			break
		}
		if len(findings) > 0 {
			break
		}
	}

	for _, key := range []string{"allowUnsigned", "allowUntrusted", "debug"} {
		for _, pathValue := range config.CollectKeyValues(loaded.Data, key) {
			if enabled, ok := config.AsBool(pathValue.Value); ok && enabled {
				severity := types.SeverityMedium
				if key != "debug" {
					severity = types.SeverityHigh
				}
				findings = append(findings, newFinding(
					"plugins."+key,
					"Plugin trust safeguard is weakened",
					"plugins",
					severity,
					"A plugin-related safety flag is enabled and should be reviewed carefully.",
					[]string{pathEvidence(pathValue.Path, key+"=true")},
					[]string{
						"Disable non-essential debug or trust-bypass flags.",
						"Load only explicitly reviewed plugins.",
					},
				))
				return findings
			}
		}
	}

	return findings
}
