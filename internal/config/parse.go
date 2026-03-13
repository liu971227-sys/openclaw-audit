package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type LoadedConfig struct {
	Path string
	Raw  []byte
	Data map[string]any
}

type PathValue struct {
	Path  string
	Value any
}

func LoadConfig(path string) (LoadedConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LoadedConfig{}, fmt.Errorf("read config: %w", err)
	}

	data := make(map[string]any)
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return LoadedConfig{}, fmt.Errorf("parse yaml: %w", err)
	}

	normalized := normalizeValue(data)
	asMap, ok := normalized.(map[string]any)
	if !ok {
		return LoadedConfig{}, fmt.Errorf("config root is not a mapping")
	}

	return LoadedConfig{Path: path, Raw: raw, Data: asMap}, nil
}

func LookupPaths(data map[string]any, dotPaths ...string) (any, string, bool) {
	for _, dotPath := range dotPaths {
		if value, ok := QueryDotPath(data, dotPath); ok {
			return value, dotPath, true
		}
	}
	return nil, "", false
}

func QueryDotPath(data map[string]any, dotPath string) (any, bool) {
	current := any(data)
	for _, segment := range strings.Split(dotPath, ".") {
		nextMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := nextMap[segment]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func CollectKeyValues(data any, key string) []PathValue {
	var collected []PathValue
	collectKeyValues("", data, key, &collected)
	return collected
}

func collectKeyValues(prefix string, data any, key string, collected *[]PathValue) {
	switch typed := data.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			currentPath := childKey
			if prefix != "" {
				currentPath = prefix + "." + childKey
			}
			if childKey == key {
				*collected = append(*collected, PathValue{Path: currentPath, Value: childValue})
			}
			collectKeyValues(currentPath, childValue, key, collected)
		}
	case []any:
		for index, childValue := range typed {
			currentPath := fmt.Sprintf("%s[%d]", prefix, index)
			collectKeyValues(currentPath, childValue, key, collected)
		}
	}
}

func AsString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	default:
		return "", false
	}
}

func AsBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "on", "1":
			return true, true
		case "false", "no", "off", "0":
			return false, true
		default:
			return false, false
		}
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}

func AsStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		flattened := make([]string, 0, len(typed))
		for _, item := range typed {
			if asString, ok := AsString(item); ok {
				flattened = append(flattened, asString)
			}
		}
		return flattened
	case string:
		return []string{typed}
	default:
		return nil
	}
}

func normalizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, child := range typed {
			normalized[key] = normalizeValue(child)
		}
		return normalized
	case map[any]any:
		normalized := make(map[string]any, len(typed))
		for key, child := range typed {
			normalized[fmt.Sprint(key)] = normalizeValue(child)
		}
		return normalized
	case []any:
		normalized := make([]any, 0, len(typed))
		for _, child := range typed {
			normalized = append(normalized, normalizeValue(child))
		}
		return normalized
	default:
		return value
	}
}
