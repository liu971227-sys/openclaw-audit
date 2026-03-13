package audit

import (
	"fmt"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunAuthenticationAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	if enabled, path, ok := lookupBool(loaded.Data, "gateway.auth.enabled", "auth.enabled"); ok && !enabled {
		findings = append(findings, newFinding(
			"auth.disabled",
			"Gateway authentication is disabled",
			"auth",
			types.SeverityCritical,
			"Explicit authentication settings indicate that gateway authentication is disabled.",
			[]string{pathEvidence(path, "authentication is disabled")},
			[]string{
				"Enable strong authentication for all remote gateway access.",
				"Prefer token-based or stronger device-bound authentication.",
			},
		))
	}

	token, tokenPath, tokenFound := lookupString(loaded.Data, "gateway.auth.token", "auth.token", "gateway.token", "token")
	if tokenFound && !looksLikePlaceholderCredential(token) && len(token) < 24 {
		findings = append(findings, newFinding(
			"auth.token.short",
			"Configured token looks weak",
			"auth",
			types.SeverityHigh,
			"The configured authentication token is unusually short and may be weak.",
			[]string{pathEvidence(tokenPath, fmt.Sprintf("token length=%d", len(token)))},
			[]string{
				"Rotate the token to a longer high-entropy value.",
				"Avoid reusing tokens from logs or chat transcripts.",
			},
		))
	}

	password, passwordPath, passwordFound := lookupString(loaded.Data, "gateway.auth.password", "auth.password", "gateway.password", "password")
	if passwordFound && !looksLikePlaceholderCredential(password) && len(password) < 12 {
		findings = append(findings, newFinding(
			"auth.password.short",
			"Configured password looks weak",
			"auth",
			types.SeverityHigh,
			"The configured password is shorter than a reasonable minimum for protecting remote gateway access.",
			[]string{pathEvidence(passwordPath, fmt.Sprintf("password length=%d", len(password)))},
			[]string{
				"Use a longer random password or switch to token-based authentication.",
				"Review whether localhost-only binding can remove the need for password exposure.",
			},
		))
	}

	if !tokenFound && !passwordFound {
		findings = append(findings, newFinding(
			"auth.settings.unverified",
			"Authentication settings could not be verified",
			"auth",
			types.SeverityMedium,
			"The scanner did not find a token or password in common config paths, so authentication posture requires manual review.",
			nil,
			[]string{
				"Confirm how gateway authentication is enforced.",
				"Document the chosen auth mechanism explicitly in config or deployment notes.",
			},
		))
	}

	return findings
}

func looksLikePlaceholderCredential(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	ignoredFragments := []string{"${", "env:", "process.env", "placeholder", "example", "sample", "redacted"}
	for _, fragment := range ignoredFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
