package types

import "sort"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation []string `json:"remediation,omitempty"`
}

type ScanResult struct {
	ToolName        string    `json:"toolName"`
	ToolVersion     string    `json:"toolVersion"`
	OpenClawVersion string    `json:"openClawVersion,omitempty"`
	Score           int       `json:"score"`
	RiskLevel       string    `json:"riskLevel"`
	Findings        []Finding `json:"findings"`
	ScannedPaths    []string  `json:"scannedPaths"`
	GeneratedAtUTC  string    `json:"generatedAtUtc"`
}

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 12
	case SeverityMedium:
		return 6
	case SeverityLow:
		return 2
	default:
		return 0
	}
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() == findings[j].Severity.Rank() {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Severity.Rank() > findings[j].Severity.Rank()
	})
}

func HighestSeverity(findings []Finding) Severity {
	highest := SeverityInfo
	for _, finding := range findings {
		if finding.Severity.Rank() > highest.Rank() {
			highest = finding.Severity
		}
	}
	return highest
}

func CalculateScore(findings []Finding) int {
	score := 100
	for _, finding := range findings {
		score -= finding.Severity.Weight()
	}
	if score < 0 {
		return 0
	}
	return score
}

func RiskLevel(score int, highest Severity) string {
	if highest == SeverityCritical {
		return "Critical"
	}
	if highest == SeverityHigh || score <= 60 {
		return "High"
	}
	if highest == SeverityMedium || score <= 80 {
		return "Medium"
	}
	if highest == SeverityLow {
		return "Low"
	}
	return "Minimal"
}
