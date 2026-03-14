package audit

import (
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunTrustedProxyAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	trustedProxies, path, ok := lookupStringSlice(loaded.Data, "gateway.trustedProxies", "trustedProxies")
	if ok {
		for _, proxy := range trustedProxies {
			if isBroadTrustedProxy(proxy) {
				findings = append(findings, newFinding(
					"proxy.trusted_proxies_broad",
					"Trusted proxy range is too broad",
					"proxy",
					types.SeverityHigh,
					"OpenClaw trusts a very broad proxy range, which increases the risk of spoofed forwarded headers or accidental trust of unapproved intermediaries.",
					[]string{pathEvidence(path, "trustedProxies contains "+proxy)},
					[]string{
						"Restrict trustedProxies to the exact reverse proxy addresses or subnets in use.",
						"Document which proxy should terminate user traffic before forwarding to OpenClaw.",
					},
				))
				break
			}
		}

		if _, _, allowUsersConfigured := lookupStringSlice(loaded.Data, "gateway.allowUsers", "allowUsers"); !allowUsersConfigured {
			findings = append(findings, newFinding(
				"proxy.allow_users_missing",
				"Trusted proxies are configured without allowUsers",
				"proxy",
				types.SeverityMedium,
				"OpenClaw trusts a reverse proxy, but the scanner did not find allowUsers in common config paths.",
				[]string{pathEvidence(path, "trustedProxies configured without allowUsers")},
				[]string{
					"Set allowUsers explicitly when trusting reverse proxy identity headers.",
					"Review the reverse proxy chain and header forwarding policy.",
				},
			))
		}
	}

	if enabled, path, ok := lookupBool(loaded.Data, "gateway.auth.allowTailscale", "auth.allowTailscale"); ok && enabled {
		findings = append(findings, newFinding(
			"proxy.allow_tailscale_enabled",
			"Tailscale header trust is enabled",
			"proxy",
			types.SeverityMedium,
			"allowTailscale is enabled. This is safe only when the gateway host and network path are trusted and not fronted by another reverse proxy.",
			[]string{pathEvidence(path, "allowTailscale=true")},
			[]string{
				"Disable allowTailscale if a reverse proxy terminates traffic in front of the gateway.",
				"Use explicit token/password auth when same-host or proxy trust is unclear.",
			},
		))
	}

	return findings
}

func RunTrustedProxyAuthAudit(loaded config.LoadedConfig) []types.Finding {
	mode, modePath, ok := lookupString(loaded.Data, "gateway.auth.mode", "auth.mode")
	if !ok || !strings.EqualFold(strings.TrimSpace(mode), "trusted-proxy") {
		return nil
	}

	var findings []types.Finding
	if _, _, proxiesConfigured := lookupStringSlice(loaded.Data, "gateway.trustedProxies", "trustedProxies"); !proxiesConfigured {
		findings = append(findings, newFinding(
			"proxy.trusted_proxy_mode_without_trusted_proxies",
			"Trusted-proxy auth mode is enabled without trustedProxies",
			"proxy",
			types.SeverityCritical,
			"trusted-proxy auth delegates authentication to the reverse proxy, but no trustedProxies allowlist was found.",
			[]string{pathEvidence(modePath, "auth.mode=trusted-proxy")},
			[]string{
				"Set gateway.trustedProxies to the exact proxy IPs or subnets.",
				"Do not enable trusted-proxy auth if any path can bypass the authenticating proxy.",
			},
		))
	}
	if _, _, allowUsersConfigured := lookupStringSlice(loaded.Data, "gateway.allowUsers", "allowUsers"); !allowUsersConfigured {
		findings = append(findings, newFinding(
			"proxy.trusted_proxy_mode_without_allow_users",
			"Trusted-proxy auth mode is enabled without allowUsers",
			"proxy",
			types.SeverityMedium,
			"trusted-proxy auth relies on the reverse proxy to assert user identity, but allowUsers was not found in common config paths.",
			[]string{pathEvidence(modePath, "auth.mode=trusted-proxy")},
			[]string{
				"Set allowUsers explicitly to the identities your proxy is allowed to assert.",
				"Confirm the reverse proxy strips and overwrites forwarded identity headers.",
			},
		))
	}

	return findings
}

func isBroadTrustedProxy(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "*", "0.0.0.0/0", "::/0":
		return true
	}
	return strings.HasSuffix(normalized, "/0")
}
