package app

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liu97/openclaw-audit/internal/audit"
	"github.com/liu97/openclaw-audit/internal/config"
	"github.com/liu97/openclaw-audit/internal/report"
	"github.com/liu97/openclaw-audit/internal/types"
)

const buildVersion = "0.1.0-dev"

type scanOptions struct {
	configPath string
	logsPath   string
	format     string
	reportPath string
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, buildVersion)
		return 0
	case "-h", "--help", "help":
		writeUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	options := scanOptions{}
	fs.StringVar(&options.configPath, "config", "", "Path to an OpenClaw config YAML file")
	fs.StringVar(&options.logsPath, "logs", "", "Path to an OpenClaw log directory")
	fs.StringVar(&options.format, "format", "terminal", "Output format: terminal or json")
	fs.StringVar(&options.reportPath, "report", "", "Optional path to write an HTML report")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	discovery, err := config.Discover(options.configPath, options.logsPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "discover OpenClaw paths: %v\n", err)
		return 2
	}
	if discovery.ConfigPath == "" {
		_, _ = fmt.Fprintln(stderr, "no OpenClaw config file found; pass --config to scan a specific file")
		return 2
	}

	loadedConfig, err := config.LoadConfig(discovery.ConfigPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config %s: %v\n", discovery.ConfigPath, err)
		return 2
	}

	var findings []types.Finding
	findings = append(findings, audit.RunGatewayAudit(loadedConfig)...)
	findings = append(findings, audit.RunAuthenticationAudit(loadedConfig)...)
	findings = append(findings, audit.RunControlUIAudit(loadedConfig)...)
	findings = append(findings, audit.RunTrustedProxyAudit(loadedConfig)...)
	findings = append(findings, audit.RunTrustedProxyAuthAudit(loadedConfig)...)
	findings = append(findings, audit.RunBrowserAudit(loadedConfig)...)
	findings = append(findings, audit.RunUnsafeContentAudit(loadedConfig)...)
	findings = append(findings, audit.RunFilesystemAudit(loadedConfig)...)
	findings = append(findings, audit.RunSecretsAudit(loadedConfig, discovery.LogPaths)...)
	findings = append(findings, audit.RunToolsAudit(loadedConfig)...)
	findings = append(findings, audit.RunPluginsAudit(loadedConfig)...)

	openClawVersion, versionFindings := audit.RunVersionAudit(loadedConfig)
	findings = append(findings, versionFindings...)

	types.SortFindings(findings)

	scannedPaths := []string{discovery.ConfigPath}
	scannedPaths = append(scannedPaths, discovery.LogPaths...)
	scannedPaths = uniquePaths(scannedPaths)

	score := types.CalculateScore(findings)
	result := types.ScanResult{
		ToolName:        "openclaw-audit",
		ToolVersion:     buildVersion,
		OpenClawVersion: openClawVersion,
		Score:           score,
		RiskLevel:       types.RiskLevel(score, types.HighestSeverity(findings)),
		Findings:        findings,
		ScannedPaths:    scannedPaths,
		GeneratedAtUTC:  time.Now().UTC().Format(time.RFC3339),
	}

	switch strings.ToLower(options.format) {
	case "terminal":
		if err := report.WriteTerminal(stdout, result); err != nil {
			_, _ = fmt.Fprintf(stderr, "render terminal report: %v\n", err)
			return 2
		}
	case "json":
		payload, err := report.RenderJSON(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "render json report: %v\n", err)
			return 2
		}
		if _, err := stdout.Write(payload); err != nil {
			_, _ = fmt.Fprintf(stderr, "write json report: %v\n", err)
			return 2
		}
	default:
		_, _ = fmt.Fprintf(stderr, "unsupported format %q; expected terminal or json\n", options.format)
		return 2
	}

	if options.reportPath != "" {
		payload, err := report.RenderHTML(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "render html report: %v\n", err)
			return 2
		}
		if err := os.MkdirAll(filepath.Dir(options.reportPath), 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "create report directory: %v\n", err)
			return 2
		}
		if err := os.WriteFile(options.reportPath, payload, 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "write report %s: %v\n", options.reportPath, err)
			return 2
		}
	}

	if len(result.Findings) == 0 || types.HighestSeverity(result.Findings) == types.SeverityInfo {
		return 0
	}
	return 1
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		cleaned := filepath.Clean(path)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique
}

func writeUsage(w io.Writer) {
	_, _ = io.WriteString(w, `openclaw-audit scans a local OpenClaw installation for risky security posture.

Usage:
  openclaw-audit scan [--config path] [--logs path] [--format terminal|json] [--report report.html]
  openclaw-audit version
`)
}
