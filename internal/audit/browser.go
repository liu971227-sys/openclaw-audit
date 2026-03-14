package audit

import (
	"net/url"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunBrowserAudit(loaded config.LoadedConfig) []types.Finding {
	_, _, browserConfigPresent := config.LookupPaths(loaded.Data, "browser", "gateway.nodes.browser")
	browserEnabled := browserConfigPresent
	if enabled, _, ok := lookupBool(loaded.Data, "browser.enabled"); ok {
		browserEnabled = enabled || browserConfigPresent
	}
	if !browserEnabled {
		return nil
	}

	var findings []types.Finding

	if enabled, path, ok := lookupBool(loaded.Data, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"); ok && enabled {
		findings = append(findings, newFinding(
			"browser.private_network_allowed",
			"Browser SSRF policy allows private-network destinations",
			"browser",
			types.SeverityMedium,
			"OpenClaw browser SSRF policy is configured to allow private or internal network destinations.",
			[]string{pathEvidence(path, "dangerouslyAllowPrivateNetwork=true")},
			[]string{
				"Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false for stricter browsing.",
				"Use allowedHostnames or hostnameAllowlist for narrowly scoped exceptions.",
			},
		))
	}
	if enabled, path, ok := lookupBool(loaded.Data, "browser.ssrfPolicy.allowPrivateNetwork"); ok && enabled {
		findings = append(findings, newFinding(
			"browser.private_network_legacy_alias",
			"Browser SSRF policy uses the legacy private-network allow flag",
			"browser",
			types.SeverityMedium,
			"A legacy browser SSRF policy flag keeps private-network destinations allowed.",
			[]string{pathEvidence(path, "allowPrivateNetwork=true")},
			[]string{
				"Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false and migrate off the legacy alias.",
			},
		))
	}
	if enabled, path, ok := lookupBool(loaded.Data, "browser.evaluateEnabled"); ok && enabled {
		findings = append(findings, newFinding(
			"browser.evaluate_enabled",
			"Browser JavaScript evaluation is enabled",
			"browser",
			types.SeverityMedium,
			"Browser page-context JavaScript evaluation is enabled, which increases prompt-injection blast radius.",
			[]string{pathEvidence(path, "evaluateEnabled=true")},
			[]string{
				"Disable browser.evaluateEnabled if you do not need arbitrary in-page JavaScript execution.",
				"Use the narrowest browser tool surface possible for agents that touch untrusted content.",
			},
		))
	}
	if mode, path, ok := lookupString(loaded.Data, "gateway.nodes.browser.mode"); ok {
		normalized := strings.ToLower(strings.TrimSpace(mode))
		if normalized != "" && normalized != "off" {
			findings = append(findings, newFinding(
				"browser.gateway_nodes_mode_enabled",
				"Browser relay mode is enabled",
				"browser",
				types.SeverityMedium,
				"Gateway browser relay or proxy routing is enabled. OpenClaw guidance recommends keeping browser relay mode off unless you need it.",
				[]string{pathEvidence(path, "gateway.nodes.browser.mode="+mode)},
				[]string{
					"Set gateway.nodes.browser.mode to off when browser relay is not required.",
					"Keep relay and CDP endpoints private and protected when browser relay must stay enabled.",
				},
			))
		}
	}

	for _, pathValue := range config.CollectKeyValues(loaded.Data, "cdpUrl") {
		cdpURL, ok := config.AsString(pathValue.Value)
		if !ok || !isRemoteCDPURL(cdpURL) {
			continue
		}
		findings = append(findings, newFinding(
			"browser.remote_cdp_url",
			"Remote CDP endpoint is configured",
			"browser",
			types.SeverityHigh,
			"A non-loopback CDP endpoint is configured. Remote CDP is powerful and should be tunneled and tightly protected.",
			[]string{pathEvidence(pathValue.Path, "cdpUrl="+cdpURL)},
			[]string{
				"Prefer loopback or an SSH/Tailscale tunnel for CDP access.",
				"Protect any remote CDP endpoint with strong network isolation and credentials.",
			},
		))
		break
	}

	return findings
}

func isRemoteCDPURL(raw string) bool {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return false
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return !strings.Contains(normalized, "127.0.0.1") && !strings.Contains(normalized, "localhost") && !strings.Contains(normalized, "::1")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return false
	}
	switch hostname {
	case "127.0.0.1", "localhost", "::1":
		return false
	default:
		return true
	}
}
