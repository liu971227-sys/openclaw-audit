package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/liu97/openclaw-audit/internal/types"
)

func WriteTerminal(w io.Writer, result types.ScanResult) error {
	if _, err := fmt.Fprintf(w, "OpenClaw Security Audit\nScore: %d/100\nRisk: %s\n", result.Score, result.RiskLevel); err != nil {
		return err
	}
	if result.OpenClawVersion != "" {
		if _, err := fmt.Fprintf(w, "OpenClaw Version: %s\n", result.OpenClawVersion); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "Generated: %s\n", result.GeneratedAtUTC); err != nil {
		return err
	}
	if len(result.ScannedPaths) > 0 {
		if _, err := fmt.Fprintf(w, "Scanned Paths:\n- %s\n", strings.Join(result.ScannedPaths, "\n- ")); err != nil {
			return err
		}
	}

	if len(result.Findings) == 0 {
		_, err := io.WriteString(w, "\nNo findings detected.\n")
		return err
	}

	if _, err := io.WriteString(w, "\nFindings:\n"); err != nil {
		return err
	}

	for _, finding := range result.Findings {
		if _, err := fmt.Fprintf(w, "- [%s] %s\n  %s\n", strings.ToUpper(string(finding.Severity)), finding.Title, finding.Summary); err != nil {
			return err
		}
		for _, evidence := range finding.Evidence {
			if _, err := fmt.Fprintf(w, "  Evidence: %s\n", evidence); err != nil {
				return err
			}
		}
		for _, remediation := range finding.Remediation {
			if _, err := fmt.Fprintf(w, "  Fix: %s\n", remediation); err != nil {
				return err
			}
		}
	}

	return nil
}
