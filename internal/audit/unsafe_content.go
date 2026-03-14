package audit

import (
	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunUnsafeContentAudit(loaded config.LoadedConfig) []types.Finding {
	for _, pathValue := range config.CollectKeyValues(loaded.Data, "allowUnsafeExternalContent") {
		if enabled, ok := config.AsBool(pathValue.Value); ok && enabled {
			return []types.Finding{newFinding(
				"content.allow_unsafe_external_content",
				"Unsafe external content bypass is enabled",
				"content",
				types.SeverityHigh,
				"OpenClaw is configured to bypass external-content safety wrapping for at least one hook or job path.",
				[]string{pathEvidence(pathValue.Path, "allowUnsafeExternalContent=true")},
				[]string{
					"Set allowUnsafeExternalContent to false except for short-lived debugging.",
					"If temporary bypass is unavoidable, isolate that agent with sandboxing and minimal tool access.",
				},
			)}
		}
	}
	return nil
}
