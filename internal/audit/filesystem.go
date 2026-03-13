package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/liu97/openclaw-audit/internal/types"
)

func RunFilesystemAudit(configPath string) []types.Finding {
	if runtime.GOOS == "windows" {
		return []types.Finding{
			newFinding(
				"filesystem.windows_acl_review",
				"Filesystem ACL review is limited on Windows",
				"filesystem",
				types.SeverityInfo,
				"The current implementation skips detailed Windows ACL analysis because POSIX permission bits are not reliable on Windows.",
				[]string{pathEvidence(configPath, "manual ACL review recommended")},
				[]string{
					"Review NTFS ACLs on config, logs, and auth profile files manually.",
					"Restrict access to the account that runs OpenClaw.",
				},
			),
		}
	}

	baseDir := filepath.Dir(configPath)
	sensitivePaths := []string{
		configPath,
		filepath.Join(baseDir, "auth-profiles.json"),
		filepath.Join(baseDir, "secrets.json"),
		filepath.Join(baseDir, "sessions"),
	}

	var findings []types.Finding
	for _, path := range sensitivePaths {
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
