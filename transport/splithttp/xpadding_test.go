package splithttp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2/hpack"
)

func TestXPadding_TokenishGeneration(t *testing.T) {
	targetLengths := []int{16, 32, 64, 128}

	for _, target := range targetLengths {
		padding := GenerateTokenishPaddingBase62(target)
		huffmanLen := int(hpack.HuffmanEncodeLength(padding))

		assert.InDelta(t, target, huffmanLen, 2, "Huffman length should be close to target")

		for _, r := range padding {
			assert.Contains(t, charsetBase62, string(r))
		}
	}
}

func TestXPadding_Validation(t *testing.T) {
	cfg := &Config{
		XPaddingMethod: "tokenish",
	}

	t.Run("ValidTokenish", func(t *testing.T) {
		padding := GenerateTokenishPaddingBase62(100)
		isValid := cfg.IsPaddingValid(padding, 90, 110, PaddingMethodTokenish)
		assert.True(t, isValid)
	})

	t.Run("InvalidLength", func(t *testing.T) {
		padding := "short"
		isValid := cfg.IsPaddingValid(padding, 100, 200, PaddingMethodRepeatX)
		assert.False(t, isValid)
	})

	t.Run("EmptyPaddingHandling", func(t *testing.T) {
		// ✨ 修正：根据 Xray 准则，即使 from=0，空字符串也必须返回 false
		assert.False(t, cfg.IsPaddingValid("", 0, 20, PaddingMethodRepeatX))
	})
}
