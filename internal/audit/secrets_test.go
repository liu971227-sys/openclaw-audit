package audit

import "testing"

func TestShouldIgnoreSecretMatch(t *testing.T) {
	if !shouldIgnoreSecretMatch([]byte("${OPENCLAW_AUTH_TOKEN}")) {
		t.Fatalf("expected env placeholder to be ignored")
	}
	if shouldIgnoreSecretMatch([]byte("sk-live-realisticlookingtoken123456789")) {
		t.Fatalf("expected real-looking token to remain detectable")
	}
}
