package report

import (
	"encoding/json"

	"github.com/liu97/openclaw-audit/internal/types"
)

func RenderJSON(result types.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
