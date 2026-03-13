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
