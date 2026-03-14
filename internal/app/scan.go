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
	"github.com/liu97/openclaw-audit/internal/harden"
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

type hardenOptions struct {
	configPath   string
	logsPath     string
	outputDir    string
	siteAddress  string
	upstream     string
	authUser     string
	passwordHash string
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "harden":
		return runHarden(args[1:], stdout, stderr)
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
	fs.StringVar(&options.configPath, "config", "", "Path to an OpenClaw config YAML or JSON file")
	fs.StringVar(&options.logsPath, "logs", "", "Path to an OpenClaw log directory")
	fs.StringVar(&options.format, "format", "terminal", "Output format: terminal or json")
	fs.StringVar(&options.reportPath, "report", "", "Optional path to write an HTML report")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	_, _, result, err := executeAudit(options.configPath, options.logsPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
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

func runHarden(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harden", flag.ContinueOnError)
	fs.SetOutput(stderr)

	options := hardenOptions{}
	fs.StringVar(&options.configPath, "config", "", "Path to an OpenClaw config YAML or JSON file")
	fs.StringVar(&options.logsPath, "logs", "", "Path to an OpenClaw log directory")
	fs.StringVar(&options.outputDir, "output-dir", filepath.Join("dist", "hardening"), "Directory to write generated hardening artifacts")
	fs.StringVar(&options.siteAddress, "site", harden.DefaultSiteAddress, "Public site address to protect with Caddy")
	fs.StringVar(&options.upstream, "upstream", harden.DefaultUpstreamAddress, "Loopback upstream for the OpenClaw gateway")
	fs.StringVar(&options.authUser, "auth-user", "admin", "Basic auth username for the generated Caddyfile")
	fs.StringVar(&options.passwordHash, "password-hash", harden.PasswordHashPlaceholder, "Hashed password for the generated Caddyfile; use caddy hash-password to replace the placeholder")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	discovery, loadedConfig, result, err := executeAudit(options.configPath, options.logsPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	artifacts := harden.Generate(loadedConfig, result, harden.Options{
		SiteAddress:  options.siteAddress,
		Upstream:     options.upstream,
		AuthUser:     options.authUser,
		PasswordHash: options.passwordHash,
	})

	if err := os.MkdirAll(options.outputDir, 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "create hardening output directory: %v\n", err)
		return 2
	}

	caddyfilePath := filepath.Join(options.outputDir, "Caddyfile")
	guidePath := filepath.Join(options.outputDir, "HARDENING.md")
	fixPreviewPath := filepath.Join(options.outputDir, "openclaw.fix-preview.json")
	if err := os.WriteFile(caddyfilePath, []byte(artifacts.Caddyfile), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "write Caddyfile: %v\n", err)
		return 2
	}
	if err := os.WriteFile(guidePath, []byte(artifacts.Guide), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "write hardening guide: %v\n", err)
		return 2
	}
	if err := os.WriteFile(fixPreviewPath, []byte(artifacts.FixPreviewJSON), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "write fix preview: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "Generated hardening artifacts for %s\n", discovery.ConfigPath)
	_, _ = fmt.Fprintf(stdout, "- %s\n", caddyfilePath)
	_, _ = fmt.Fprintf(stdout, "- %s\n", guidePath)
	_, _ = fmt.Fprintf(stdout, "- %s\n", fixPreviewPath)
	_, _ = fmt.Fprintf(stdout, "Current scan score: %d/100 (%s)\n", result.Score, result.RiskLevel)
	if options.passwordHash == harden.PasswordHashPlaceholder {
		_, _ = fmt.Fprintln(stdout, "Replace the placeholder password hash in the generated Caddyfile with: caddy hash-password --plaintext 'change-me-now'")
	}
	return 0
}

func executeAudit(configPath, logsPath string) (config.Discovery, config.LoadedConfig, types.ScanResult, error) {
	discovery, err := config.Discover(configPath, logsPath)
	if err != nil {
		return config.Discovery{}, config.LoadedConfig{}, types.ScanResult{}, fmt.Errorf("discover OpenClaw paths: %w", err)
	}
	if discovery.ConfigPath == "" {
		return discovery, config.LoadedConfig{}, types.ScanResult{}, fmt.Errorf("no OpenClaw config file found; pass --config to scan a specific file")
	}

	loadedConfig, err := config.LoadConfig(discovery.ConfigPath)
	if err != nil {
		return discovery, config.LoadedConfig{}, types.ScanResult{}, fmt.Errorf("load config %s: %w", discovery.ConfigPath, err)
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

	return discovery, loadedConfig, result, nil
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
  openclaw-audit harden [--config path] [--logs path] [--output-dir dir] [--site openclaw.example.com] [--upstream 127.0.0.1:18789]
  openclaw-audit version
`)
}
