package harden

import (
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
