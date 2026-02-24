package splithttp

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
)

func TestConfig_PathNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/xhttp", "/xhttp/"},
		{"xhttp/", "/xhttp/"},
		{"", "/"},
		{"/api/v1?query=1", "/api/v1/"},
	}

	for _, tt := range tests {
		cfg := &Config{Path: tt.input}
		assert.Equal(t, tt.expected, cfg.GetNormalizedPath())
	}
}

func TestConfig_MetaExtraction(t *testing.T) {
	cfg := &Config{
		SessionPlacement: PlacementHeader,
		SessionKey:       "X-Sess",
		SeqPlacement:     PlacementPath,
	}
	basePath := "/sh/"

	t.Run("ExtractFromMixedLocations", func(t *testing.T) {
		// ✨ 修正：当 Seq 单独在 Path 时，它占据路径的第一额外段
		req, _ := http.NewRequest("POST", "http://local/sh/123", nil)
		req.Header.Set("X-Sess", "sid-99")

		sid, seq := cfg.ExtractMetaFromRequest(req, basePath)
		assert.Equal(t, "sid-99", sid)
		assert.Equal(t, "123", seq)
	})

	t.Run("ExtractBothFromPath", func(t *testing.T) {
		pathCfg := &Config{
			SessionPlacement: PlacementPath,
			SeqPlacement:     PlacementPath,
		}
		req, _ := http.NewRequest("POST", "http://local/sh/my-session/456", nil)
		sid, seq := pathCfg.ExtractMetaFromRequest(req, basePath)
		assert.Equal(t, "my-session", sid)
		assert.Equal(t, "456", seq)
	})
}
