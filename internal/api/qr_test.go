package api

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIHandler_GenerateQRWithLogo(t *testing.T) {
	h, _, _, _, _ := setupTest()

	t.Run("Fallback when logo missing", func(t *testing.T) {
		pngData, err := h.generateQRWithLogo("https://example.com")
		assert.NoError(t, err)
		assert.NotEmpty(t, pngData)

		// Verify it's a valid PNG
		_, err = png.Decode(bytes.NewReader(pngData))
		assert.NoError(t, err)
	})

	t.Run("Success with logo", func(t *testing.T) {
		// Write the dummy logo into an isolated temp dir so the test never
		// touches the real source tree. t.TempDir() is auto-cleaned.
		logoPath := filepath.Join(t.TempDir(), "favicon-color.png")

		// Create a small dummy PNG logo
		img := image.NewRGBA(image.Rect(0, 0, 32, 32))
		for x := 0; x < 32; x++ {
			for y := 0; y < 32; y++ {
				img.Set(x, y, color.RGBA{255, 0, 0, 255})
			}
		}

		f, err := os.Create(logoPath)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		err = png.Encode(f, img)
		require.NoError(t, err)

		pngData, err := h.generateQRWithLogoFromPath("https://example.com", logoPath)
		assert.NoError(t, err)
		assert.NotEmpty(t, pngData)

		// Verify it's a valid PNG
		decoded, err := png.Decode(bytes.NewReader(pngData))
		assert.NoError(t, err)
		assert.Equal(t, 256, decoded.Bounds().Dx())
		assert.Equal(t, 256, decoded.Bounds().Dy())
	})

	t.Run("Fallback when logo is invalid image", func(t *testing.T) {
		logoPath := filepath.Join(t.TempDir(), "favicon-color.png")
		err := os.WriteFile(logoPath, []byte("not a png"), 0644)
		require.NoError(t, err)

		pngData, err := h.generateQRWithLogoFromPath("https://example.com", logoPath)
		assert.NoError(t, err)
		assert.NotEmpty(t, pngData)

		_, err = png.Decode(bytes.NewReader(pngData))
		assert.NoError(t, err)
	})
}
