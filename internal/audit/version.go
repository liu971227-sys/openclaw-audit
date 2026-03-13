package audit

import (
	"os/exec"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/rules"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunVersionAudit(loaded config.LoadedConfig) (string, []types.Finding) {
	versionString := discoverVersionString(loaded)
	if versionString == "" {
		return "", []types.Finding{
			newFinding(
				"version.unknown",
				"OpenClaw version could not be determined",
				"version",
				types.SeverityLow,
				"The scanner could not determine the installed OpenClaw version from config or the local openclaw binary.",
				nil,
				[]string{
					"Ensure the openclaw binary is available in PATH, or document the deployed version next to config.",
				},
			),
		}
	}

	currentVersion, err := rules.ParseOpenClawVersion(versionString)
	if err != nil {
		return versionString, []types.Finding{
			newFinding(
				"version.unparsed",
				"OpenClaw version could not be parsed",
				"version",
				types.SeverityLow,
				"The scanner found a version string but could not parse it as a date-based OpenClaw release.",
				[]string{"raw version=" + versionString},
				[]string{
					"Confirm the installed OpenClaw version manually.",
				},
			),
		}
	}

	baseline := rules.SecureBaselineVersion()
	if currentVersion.Less(baseline) {
		return versionString, []types.Finding{
			newFinding(
				"version.below_baseline",
				"OpenClaw version is below the secure baseline",
				"version",
				types.SeverityHigh,
				"The detected OpenClaw version is older than the baked-in secure baseline and should be upgraded.",
				[]string{"detected version=" + currentVersion.String(), "baseline=" + baseline.String()},
				[]string{
					"Upgrade OpenClaw to the secure baseline or newer.",
					"Review recent OpenClaw security advisories before exposing remote access.",
				},
			),
		}
	}

	return versionString, nil
}

func discoverVersionString(loaded config.LoadedConfig) string {
	if versionString, _, ok := lookupString(loaded.Data, "version", "openclaw.version"); ok {
		if extracted := rules.ExtractVersionString(versionString); extracted != "" {
			return extracted
		}
	}

	if path, err := exec.LookPath("openclaw"); err == nil {
		output, cmdErr := exec.Command(path, "--version").CombinedOutput()
		if cmdErr == nil {
			return rules.ExtractVersionString(strings.TrimSpace(string(output)))
		}
	}

	return ""
}
