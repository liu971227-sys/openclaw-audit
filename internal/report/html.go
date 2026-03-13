package report

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/liu97/openclaw-audit/internal/types"
)

//go:embed report_template.html
var reportTemplate string

func RenderHTML(result types.ScanResult) ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(value types.Severity) string {
			return strings.ToLower(string(value))
		},
	}).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, result); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
