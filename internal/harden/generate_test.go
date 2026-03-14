package harden

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func TestGenerateIncludesProxyHeadersAndAuth(t *testing.T) {
	artifacts := Generate(config.LoadedConfig{Path: "/tmp/openclaw.json"}, types.ScanResult{}, Options{})
	if !strings.Contains(artifacts.Caddyfile, "basic_auth") {
		t.Fatalf("expected generated Caddyfile to include basic_auth")
	}
	if !strings.Contains(artifacts.Caddyfile, "header_up -X-Forwarded-User") {
		t.Fatalf("expected generated Caddyfile to strip X-Forwarded-User")
	}
	if !strings.Contains(artifacts.Caddyfile, DefaultUpstreamAddress) {
		t.Fatalf("expected generated Caddyfile to use default upstream")
	}
	if !strings.Contains(artifacts.Guide, "OpenClaw Hardening Guide") {
		t.Fatalf("expected generated guide heading")
	}
}

func TestGenerateIncludesFixPreview(t *testing.T) {
	artifacts := Generate(
		config.LoadedConfig{Path: "/tmp/openclaw.json"},
		types.ScanResult{Findings: []types.Finding{{ID: "proxy.trusted_proxies_broad"}, {ID: "content.allow_unsafe_external_content"}}},
		Options{},
	)

	var preview FixPreview
	if err := json.Unmarshal([]byte(artifacts.FixPreviewJSON), &preview); err != nil {
		t.Fatalf("unmarshal fix preview: %v", err)
	}
	gateway, ok := preview.Suggested["gateway"].(map[string]any)
	if !ok {
		t.Fatalf("expected gateway section in fix preview")
	}
	if gateway["bind"] != "127.0.0.1" {
		t.Fatalf("expected bind fix to be present")
	}
	if _, ok := preview.Suggested["hooks"].(map[string]any); !ok {
		t.Fatalf("expected hook fix preview when unsafe external content is found")
	}
}
