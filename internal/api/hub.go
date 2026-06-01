package api

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	zlog "github.com/rs/zerolog/log"
)

// wsClient wraps a websocket connection with a write mutex. gorilla/websocket
// does not support concurrent writers, and a single connection is written to
// from two goroutines: the Hub broadcast loop (event messages) and the per-
// connection handler (keep-alive pings). All writes must go through writeMessage
// so they serialize on writeMu.
type wsClient struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (c *wsClient) writeMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteMessage(messageType, data)
}

type Hub struct {
	clients    map[*wsClient]bool
	register   chan *wsClient
	unregister chan *wsClient
	stop       chan struct{}
	mu         sync.Mutex
	redis      *redis.Client
	channel    string
}

func NewHub(rdb *redis.Client) *Hub {
	return &Hub{
		clients:    make(map[*wsClient]bool),
		register:   make(chan *wsClient),
		unregister: make(chan *wsClient),
		stop:       make(chan struct{}),
		redis:      rdb,
		channel:    "blocklist_events",
	}
}

func (h *Hub) Run() {
	ctx := context.Background()
	pubsub := h.redis.Subscribe(ctx, h.channel)
	defer func() { _ = pubsub.Close() }()

	ch := pubsub.Channel()

	for {
		select {
		case <-h.stop:
			return
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				_ = client.conn.Close()
			}
			h.mu.Unlock()
		case msg := <-ch:
			h.mu.Lock()
			for client := range h.clients {
				err := client.writeMessage(websocket.TextMessage, []byte(msg.Payload))
				if err != nil {
					_ = client.conn.Close()
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) BroadcastEvent(action string, data interface{}) {
	event := map[string]interface{}{
		"action": action,
		"data":   data,
	}
	msg, _ := json.Marshal(event)

	err := h.redis.Publish(context.Background(), h.channel, msg).Err()
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to publish event to Redis")
	}
}

func (h *Hub) Stop() {
	close(h.stop)
}
