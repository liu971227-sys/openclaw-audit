package audit

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/rules"
	"github.com/liu97/openclaw-audit/internal/types"
)

const (
	maxScannedFileCount = 24
	maxScannedFileSize  = 8 << 20
)

func RunSecretsAudit(loaded config.LoadedConfig, logPaths []string) []types.Finding {
	candidateFiles := []string{loaded.Path}
	candidateFiles = append(candidateFiles, gatherLogFiles(logPaths)...)

	findings := make([]types.Finding, 0)
	patterns := rules.DefaultSecretPatterns()
	seenFiles := 0

	for _, path := range candidateFiles {
		if seenFiles >= maxScannedFileCount {
			break
		}

		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() > maxScannedFileSize {
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		seenFiles++

		for _, pattern := range patterns {
			matches := pattern.Regex.FindAll(content, -1)
			realMatchCount := 0
			for _, match := range matches {
				if shouldIgnoreSecretMatch(match) {
					continue
				}
				realMatchCount++
			}
			if realMatchCount == 0 {
				continue
			}

			severity := types.SeverityHigh
			if strings.Contains(pattern.ID, "generic") {
				severity = types.SeverityMedium
			}

			findings = append(findings, newFinding(
				"secrets."+pattern.ID+"."+filepath.Base(path),
				"Potential secret material found",
				"secrets",
				severity,
				"A likely secret pattern was detected in an OpenClaw config or log file.",
				[]string{fmt.Sprintf("%s matched %s %d time(s)", displayPath(path), pattern.Label, realMatchCount)},
				[]string{
					"Rotate any real secret value found in the file.",
					"Remove or redact historical logs that contain credentials.",
					"Prefer environment variables or a dedicated secret store instead of inline secrets.",
				},
			))
		}
	}

	return findings
}

func shouldIgnoreSecretMatch(match []byte) bool {
	normalized := strings.ToLower(string(bytes.TrimSpace(match)))
	ignoredFragments := []string{
		"${",
		"env:",
		"process.env",
		"placeholder",
		"example",
		"sample",
		"redacted",
	}
	for _, fragment := range ignoredFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func gatherLogFiles(logPaths []string) []string {
	files := make([]string, 0)
	for _, logPath := range logPaths {
		_ = filepath.WalkDir(logPath, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry == nil || entry.IsDir() {
				return nil
			}
			files = append(files, path)
			if len(files) >= maxScannedFileCount {
				return fs.SkipAll
			}
			return nil
		})
		if len(files) >= maxScannedFileCount {
			break
		}
	}
	return files
}
