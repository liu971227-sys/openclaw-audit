package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var versionPattern = regexp.MustCompile(`\b(\d{4}\.\d{1,2}\.\d{1,2})\b`)

type OpenClawVersion struct {
	Year  int
	Month int
	Day   int
}

func SecureBaselineVersion() OpenClawVersion {
	return OpenClawVersion{Year: 2026, Month: 2, Day: 25}
}

func ExtractVersionString(raw string) string {
	match := versionPattern.FindStringSubmatch(raw)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func ParseOpenClawVersion(raw string) (OpenClawVersion, error) {
	versionString := ExtractVersionString(raw)
	if versionString == "" {
		return OpenClawVersion{}, fmt.Errorf("no date-based version found in %q", raw)
	}

	segments := strings.Split(versionString, ".")
	if len(segments) != 3 {
		return OpenClawVersion{}, fmt.Errorf("unexpected version format %q", raw)
	}

	year, err := strconv.Atoi(segments[0])
	if err != nil {
		return OpenClawVersion{}, fmt.Errorf("parse version year: %w", err)
	}
	month, err := strconv.Atoi(segments[1])
	if err != nil {
		return OpenClawVersion{}, fmt.Errorf("parse version month: %w", err)
	}
	day, err := strconv.Atoi(segments[2])
	if err != nil {
		return OpenClawVersion{}, fmt.Errorf("parse version day: %w", err)
	}

	return OpenClawVersion{Year: year, Month: month, Day: day}, nil
}

func (v OpenClawVersion) Less(other OpenClawVersion) bool {
	if v.Year != other.Year {
		return v.Year < other.Year
	}
	if v.Month != other.Month {
		return v.Month < other.Month
	}
	return v.Day < other.Day
}

func (v OpenClawVersion) String() string {
	return fmt.Sprintf("%04d.%d.%d", v.Year, v.Month, v.Day)
}
