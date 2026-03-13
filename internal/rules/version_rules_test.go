package rules

import "testing"

func TestParseOpenClawVersion(t *testing.T) {
	version, err := ParseOpenClawVersion("openclaw 2026.2.25")
	if err != nil {
		t.Fatalf("expected version to parse, got error: %v", err)
	}
	if version.String() != "2026.2.25" {
		t.Fatalf("unexpected version string: %s", version.String())
	}
}

func TestVersionLess(t *testing.T) {
	older, err := ParseOpenClawVersion("2026.2.24")
	if err != nil {
		t.Fatalf("parse older version: %v", err)
	}
	newer, err := ParseOpenClawVersion("2026.2.25")
	if err != nil {
		t.Fatalf("parse newer version: %v", err)
	}
	if !older.Less(newer) {
		t.Fatalf("expected older version to compare less than newer version")
	}
}
