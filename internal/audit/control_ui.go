package audit

import (
	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunControlUIAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	if enabled, path, ok := lookupBool(loaded.Data, "gateway.controlUi.allowInsecureAuth"); ok && enabled {
		findings = append(findings, newFinding(
			"control-ui.allow_insecure_auth",
			"Control UI insecure auth is enabled",
			"control-ui",
			types.SeverityHigh,
			"OpenClaw control UI appears to allow insecure authentication, which weakens the boundary protecting the management surface.",
			[]string{pathEvidence(path, "allowInsecureAuth=true")},
			[]string{
				"Disable allowInsecureAuth.",
				"Require stronger auth before exposing the Control UI remotely.",
			},
		))
	}

	if enabled, path, ok := lookupBool(loaded.Data, "gateway.controlUi.dangerouslyDisableDeviceAuth"); ok && enabled {
		findings = append(findings, newFinding(
			"control-ui.device_auth_disabled",
			"Control UI device auth is disabled",
			"control-ui",
			types.SeverityCritical,
			"The control UI device authentication safeguard appears to be disabled.",
			[]string{pathEvidence(path, "dangerouslyDisableDeviceAuth=true")},
			[]string{
				"Re-enable device authentication immediately.",
				"Review who can currently reach the Control UI and rotate any exposed credentials.",
			},
		))
	}

	return findings
}
