package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/types"
)

var syncedFolderFragments = []string{
	"onedrive",
	"dropbox",
	"google drive",
	"googledrive",
	"icloud",
	"cloudstorage",
	"mobile documents",
	"box",
	"synology drive",
}

func RunFilesystemAudit(loaded config.LoadedConfig) []types.Finding {
	baseDir := filepath.Dir(loaded.Path)
	stateDir, stateDirPath := resolveStateDir(loaded, baseDir)
	credentialsDir := filepath.Join(stateDir, "credentials")

	var findings []types.Finding
	findings = append(findings, runPathRiskAudit(stateDir, stateDirPath, "filesystem.state_dir")...)
	findings = append(findings, runPathRiskAudit(credentialsDir, filepath.Join(stateDirPath, "credentials"), "filesystem.credentials_dir")...)

	sensitivePaths := []string{
		loaded.Path,
		stateDir,
		credentialsDir,
		filepath.Join(stateDir, "auth-profiles.json"),
		filepath.Join(stateDir, "secrets.json"),
		filepath.Join(stateDir, "sessions"),
	}

	if runtime.GOOS == "windows" {
		findings = append(findings, newFinding(
			"filesystem.windows_acl_review",
			"Filesystem ACL review is limited on Windows",
			"filesystem",
			types.SeverityInfo,
			"The current implementation skips detailed Windows ACL analysis because POSIX permission bits are not reliable on Windows.",
			[]string{pathEvidence(loaded.Path, "manual ACL review recommended")},
			[]string{
				"Review NTFS ACLs on config, state, credentials, and session files manually.",
				"Restrict access to the account that runs OpenClaw.",
			},
		))
		return findings
	}

	for _, path := range uniqueStrings(sensitivePaths) {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		perms := info.Mode().Perm()
		if info.IsDir() {
			if perms&0o022 != 0 {
				findings = append(findings, newFinding(
					"filesystem.directory_permissions",
					"Sensitive directory is writable beyond the owner",
					"filesystem",
					types.SeverityMedium,
					"A sensitive OpenClaw directory appears writable by group or others.",
					[]string{fmt.Sprintf("%s mode=%#o", displayPath(path), perms)},
					[]string{
						"Restrict directory permissions to the owner where possible.",
						"Re-check whether shared accounts or service users need write access.",
					},
				))
			}
			continue
		}

		if perms&0o077 != 0 {
			findings = append(findings, newFinding(
				"filesystem.file_permissions",
				"Sensitive file is accessible beyond the owner",
				"filesystem",
				types.SeverityHigh,
				"A sensitive OpenClaw file appears readable or writable by group or others.",
				[]string{fmt.Sprintf("%s mode=%#o", displayPath(path), perms)},
				[]string{
					"Restrict sensitive files to owner-only permissions.",
					"Rotate any credentials stored in files that were broadly readable.",
				},
			))
		}
	}

	return findings
}

func runPathRiskAudit(path string, configuredFrom string, findingPrefix string) []types.Finding {
	if path == "" {
		return nil
	}

	var findings []types.Finding
	if isSyncedFolderPath(path) {
		findings = append(findings, newFinding(
			findingPrefix+".synced_folder",
			"Sensitive OpenClaw state is stored in a synced folder",
			"filesystem",
			types.SeverityHigh,
			"The configured OpenClaw state path appears to live inside a cloud-synced folder, which can leak credentials or create session and file-lock races.",
			[]string{pathEvidence(configuredFrom, path)},
			[]string{
				"Move the OpenClaw state directory to a local non-synced path such as ~/.openclaw.",
				"Keep credentials, sessions, and extension state off OneDrive, iCloud, Dropbox, and similar sync roots.",
			},
		))
	}

	resolvedPath, isLinked, err := resolveLinkedPath(path)
	if err == nil && isLinked {
		findings = append(findings, newFinding(
			findingPrefix+".symlink",
			"Sensitive OpenClaw state path resolves through a link",
			"filesystem",
			types.SeverityMedium,
			"The configured OpenClaw path resolves through a symlink or junction. This can hide the real storage location and bypass path-based assumptions.",
			[]string{pathEvidence(configuredFrom, fmt.Sprintf("configured=%s resolved=%s", displayPath(path), displayPath(resolvedPath)))},
			[]string{
				"Store OpenClaw state directly in a local directory instead of via symlink or junction when possible.",
				"If the link target is intentional, review the target path for sync, sharing, and backup exposure.",
			},
		))
		if isSyncedFolderPath(resolvedPath) {
			findings = append(findings, newFinding(
				findingPrefix+".resolved_synced_folder",
				"Linked OpenClaw state resolves into a synced folder",
				"filesystem",
				types.SeverityHigh,
				"The configured OpenClaw path resolves into a cloud-synced folder after following a link target.",
				[]string{pathEvidence(configuredFrom, fmt.Sprintf("resolved=%s", displayPath(resolvedPath)))},
				[]string{
					"Move the real target directory to a local non-synced path.",
					"Avoid using symlinks or junctions that hide synced storage behind normal-looking local paths.",
				},
			))
		}
	}

	return findings
}

func resolveStateDir(loaded config.LoadedConfig, baseDir string) (string, string) {
	if stateDir := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")); stateDir != "" {
		return expandHomePath(stateDir), "$OPENCLAW_STATE_DIR"
	}

	if configured, path, ok := lookupString(loaded.Data, "fs.state_dir", "filesystem.stateDir", "stateDir"); ok {
		return expandHomePath(configured), path
	}

	return baseDir, filepath.Dir(loaded.Path)
}

func isSyncedFolderPath(path string) bool {
	normalized := strings.ToLower(filepath.Clean(path))
	for _, fragment := range syncedFolderFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func resolveLinkedPath(path string) (string, bool, error) {
	cleaned := expandHomePath(path)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return cleaned, false, nil
		}
		return "", false, err
	}
	if resolved == "" {
		return cleaned, false, nil
	}
	return resolved, !pathsEqual(cleaned, resolved), nil
}

func pathsEqual(left, right string) bool {
	leftClean := filepath.Clean(left)
	rightClean := filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftClean, rightClean)
	}
	return leftClean == rightClean
}

func expandHomePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") || trimmed == "~" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			if trimmed == "~" {
				return homeDir
			}
			return filepath.Join(homeDir, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return trimmed
}
