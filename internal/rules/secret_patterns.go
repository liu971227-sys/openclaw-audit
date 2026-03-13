package rules

import "regexp"

type SecretPattern struct {
	ID    string
	Label string
	Regex *regexp.Regexp
}

func DefaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{ID: "openai_key", Label: "OpenAI-style API key", Regex: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`)},
		{ID: "telegram_bot_token", Label: "Telegram bot token", Regex: regexp.MustCompile(`\b\d{7,12}:[A-Za-z0-9_-]{20,}\b`)},
		{ID: "aws_access_key", Label: "AWS access key", Regex: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{ID: "bearer_token", Label: "Bearer token", Regex: regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b`)},
		{ID: "generic_assigned_secret", Label: "Assigned token or secret", Regex: regexp.MustCompile(`(?i)\b(token|secret|api[_-]?key|password)\b\s*[:=]\s*['"]?[A-Za-z0-9._:-]{12,}`)},
	}
}
