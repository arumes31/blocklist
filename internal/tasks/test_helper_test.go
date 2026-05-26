package tasks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
)

func newTestClient(server *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
		},
	}
}
