package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Discovery struct {
	ConfigPath string
	LogPaths   []string
}

func Discover(explicitConfigPath, explicitLogsPath string) (Discovery, error) {
	var discovery Discovery

	configCandidates, err := configCandidates(explicitConfigPath)
	if err != nil {
		return discovery, err
	}
	discovery.ConfigPath = firstExistingPath(configCandidates)

	logCandidates, err := logCandidates(explicitLogsPath)
	if err != nil {
		return discovery, err
	}
	discovery.LogPaths = existingPaths(logCandidates)

	return discovery, nil
}

func configCandidates(explicitConfigPath string) ([]string, error) {
	if explicitConfigPath != "" {
		return []string{explicitConfigPath}, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine user home directory: %w", err)
	}

	candidates := []string{
		os.Getenv("OPENCLAW_CONFIG"),
		filepath.Join(homeDir, ".openclaw", "config.yaml"),
		filepath.Join(homeDir, ".openclaw", "config.yml"),
		filepath.Join(homeDir, ".config", "openclaw", "config.yaml"),
		filepath.Join(homeDir, ".config", "openclaw", "config.yml"),
	}

	if appData := os.Getenv("APPDATA"); appData != "" {
		candidates = append(candidates,
			filepath.Join(appData, "OpenClaw", "config.yaml"),
			filepath.Join(appData, "OpenClaw", "config.yml"),
		)
	}

	return compactPaths(candidates), nil
}

func logCandidates(explicitLogsPath string) ([]string, error) {
	if explicitLogsPath != "" {
		return []string{explicitLogsPath}, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine user home directory: %w", err)
	}

	candidates := []string{
		filepath.Join(homeDir, ".openclaw", "logs"),
		filepath.Join(homeDir, ".config", "openclaw", "logs"),
	}

	if appData := os.Getenv("APPDATA"); appData != "" {
		candidates = append(candidates, filepath.Join(appData, "OpenClaw", "logs"))
	}

	return compactPaths(candidates), nil
}

func compactPaths(paths []string) []string {
	compacted := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))

	for _, path := range paths {
		if path == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		compacted = append(compacted, cleaned)
	}

	return compacted
}

func firstExistingPath(paths []string) string {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		return path
	}
	return ""
}

func existingPaths(paths []string) []string {
	existing := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		existing = append(existing, path)
	}
	return existing
}
