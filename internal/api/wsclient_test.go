package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

// TestWSClient_ConcurrentWrites verifies that wsClient serializes concurrent
// writes to a single websocket connection. gorilla/websocket does not allow
// concurrent writers; in production the Hub broadcast loop and the per-connection
// keep-alive pinger both write to the same conn. Run with -race to detect a
// regression that drops the per-connection write mutex.
func TestWSClient_ConcurrentWrites(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain reads until the client closes.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := &wsClient{conn: conn}

	// Two writers contend for the same connection: one sending text frames
	// (like the Hub broadcast) and one sending pings (like the keep-alive loop).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := client.writeMessage(websocket.TextMessage, []byte("event")); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := client.writeMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}
