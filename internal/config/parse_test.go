package config

import "testing"

func TestQueryDotPath(t *testing.T) {
	data := map[string]any{
		"gateway": map[string]any{
			"controlUi": map[string]any{
				"allowInsecureAuth": true,
			},
		},
	}

	value, ok := QueryDotPath(data, "gateway.controlUi.allowInsecureAuth")
	if !ok {
		t.Fatalf("expected nested value to be found")
	}

	asBool, ok := AsBool(value)
	if !ok || !asBool {
		t.Fatalf("expected nested value to be true, got %#v", value)
	}
}

func TestCollectKeyValues(t *testing.T) {
	data := map[string]any{
		"tools": map[string]any{
			"profile": "default",
			"child": map[string]any{
				"profile": "elevated",
			},
		},
	}

	results := CollectKeyValues(data, "profile")
	if len(results) != 2 {
		t.Fatalf("expected 2 collected values, got %d", len(results))
	}
}
