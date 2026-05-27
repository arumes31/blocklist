package api

import (
	"bytes"
	"image/png"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateQRWithLogo(t *testing.T) {
	h := &APIHandler{}

	t.Run("basic_qr_generation", func(t *testing.T) {
		url := "https://example.com"
		data, err := h.generateQRWithLogo(url)

		assert.NoError(t, err)
		assert.NotNil(t, data)
		assert.True(t, len(data) > 0)

		// Verify it's a valid PNG
		img, err := png.Decode(bytes.NewReader(data))
		assert.NoError(t, err)

		// Verify dimensions (256x256 as specified in the code)
		assert.Equal(t, 256, img.Bounds().Dx())
		assert.Equal(t, 256, img.Bounds().Dy())
	})

	t.Run("empty_url_error", func(t *testing.T) {
		data, err := h.generateQRWithLogo("")
		assert.Error(t, err)
		assert.Nil(t, data)
	})
}
