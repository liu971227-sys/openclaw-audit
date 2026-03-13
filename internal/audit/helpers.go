package audit

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

func newFinding(id, title, category string, severity types.Severity, summary string, evidence, remediation []string) types.Finding {
	status := "warn"
	if severity == types.SeverityHigh || severity == types.SeverityCritical {
		status = "fail"
	}
	if severity == types.SeverityInfo {
		status = "info"
	}

	return types.Finding{
		ID:          id,
		Title:       title,
		Severity:    severity,
		Category:    category,
		Status:      status,
		Summary:     summary,
		Evidence:    evidence,
		Remediation: remediation,
	}
}

func lookupString(data map[string]any, dotPaths ...string) (string, string, bool) {
	value, path, ok := config.LookupPaths(data, dotPaths...)
	if !ok {
		return "", "", false
	}
	asString, ok := config.AsString(value)
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(asString), path, true
}

func lookupBool(data map[string]any, dotPaths ...string) (bool, string, bool) {
	value, path, ok := config.LookupPaths(data, dotPaths...)
	if !ok {
		return false, "", false
	}
	asBool, ok := config.AsBool(value)
	if !ok {
		return false, "", false
	}
	return asBool, path, true
}

func lookupStringSlice(data map[string]any, dotPaths ...string) ([]string, string, bool) {
	value, path, ok := config.LookupPaths(data, dotPaths...)
	if !ok {
		return nil, "", false
	}
	values := config.AsStringSlice(value)
	if len(values) == 0 {
		return nil, "", false
	}
	return values, path, true
}

func nonEmpty(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	case bool:
		return typed
	default:
		return value != nil
	}
}

func pathEvidence(path, message string) string {
	if path == "" {
		return message
	}
	return fmt.Sprintf("%s (%s)", message, path)
}

func displayPath(path string) string {
	return filepath.Clean(path)
}
