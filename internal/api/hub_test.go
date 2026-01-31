package api

import (
	"testing"
)

func TestHub_BroadcastEvent(t *testing.T) {
	h := NewHub()
	// Just test that it doesn't panic when no clients are registered
	h.BroadcastEvent("test", map[string]string{"foo": "bar"})
}
