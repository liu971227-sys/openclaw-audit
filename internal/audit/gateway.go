package audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func RunGatewayAudit(loaded config.LoadedConfig) []types.Finding {
	var findings []types.Finding

	bindValue, path, ok := lookupString(loaded.Data, "gateway.bind", "gateway.host", "bind")
	if !ok {
		findings = append(findings, newFinding(
			"gateway.bind.missing",
			"Gateway bind setting not found",
			"exposure",
			types.SeverityMedium,
			"The scanner could not find gateway.bind in common config paths, so gateway exposure could not be fully validated.",
			nil,
			[]string{
				"Add an explicit gateway.bind value to the OpenClaw config.",
				"Prefer loopback unless remote access is intentionally protected.",
			},
		))
	} else {
		classification := classifyBindAddress(bindValue)
		switch classification {
		case "public":
			findings = append(findings, newFinding(
				"gateway.bind.public",
				"Gateway listens on all interfaces",
				"exposure",
				types.SeverityCritical,
				"OpenClaw appears to listen on all interfaces, which can expose the gateway to the local network or public internet.",
				[]string{pathEvidence(path, fmt.Sprintf("gateway.bind=%s", bindValue))},
				[]string{
					"Set gateway.bind to loopback or 127.0.0.1.",
					"Only expose the gateway behind strong authentication and a trusted reverse proxy.",
				},
			))
		case "lan":
			findings = append(findings, newFinding(
				"gateway.bind.lan",
				"Gateway appears reachable on a non-loopback address",
				"exposure",
				types.SeverityHigh,
				"OpenClaw appears to listen on a non-loopback address, which may expose it to other hosts on the local network.",
				[]string{pathEvidence(path, fmt.Sprintf("gateway.bind=%s", bindValue))},
				[]string{
					"Use loopback if remote access is not required.",
					"Restrict access with strong authentication and network controls.",
				},
			))
		}
	}

	for _, dotPath := range []string{"gateway.tailscale.serve", "gateway.tailscale.funnel", "tailscale.serve", "tailscale.funnel"} {
		enabled, matchedPath, ok := lookupBool(loaded.Data, dotPath)
		if ok && enabled {
			findings = append(findings, newFinding(
				"gateway.remote.tailscale",
				"Tailscale remote publishing is enabled",
				"exposure",
				types.SeverityHigh,
				"OpenClaw appears to be published through Tailscale Serve or Funnel, which widens remote reachability and should be reviewed carefully.",
				[]string{pathEvidence(matchedPath, "Tailscale publishing is enabled")},
				[]string{
					"Verify that only intended users can reach the gateway.",
					"Review authentication and reverse proxy restrictions before exposing OpenClaw remotely.",
				},
			))
			break
		}
	}

	return findings
}

func classifyBindAddress(bindValue string) string {
	normalized := strings.ToLower(strings.TrimSpace(bindValue))

	switch normalized {
	case "", "loopback", "127.0.0.1", "localhost", "::1":
		return "local"
	case "0.0.0.0", "::", "[::]", "*":
		return "public"
	}

	if strings.HasPrefix(normalized, "10.") || strings.HasPrefix(normalized, "192.168.") {
		return "lan"
	}
	if strings.HasPrefix(normalized, "172.") {
		parts := strings.Split(normalized, ".")
		if len(parts) >= 2 {
			secondOctet, err := strconv.Atoi(parts[1])
			if err == nil && secondOctet >= 16 && secondOctet <= 31 {
				return "lan"
			}
		}
	}

	return "lan"
}
