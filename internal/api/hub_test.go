package api

import (
	"testing"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestHub_BroadcastEvent(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	
	h := NewHub(rdb)
	// Just test that it doesn't panic when no clients are registered
	h.BroadcastEvent("test", map[string]string{"foo": "bar"})
}
