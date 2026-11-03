package service

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"

	"blocklist/internal/config"

	"github.com/stretchr/testify/require"
)

// fakeSMTP accepts one connection, advertises no STARTTLS and records every
// command it receives.
func fakeSMTP(t *testing.T) (host string, port int, commands <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		var seen []string
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		reply := func(s string) { _, _ = rw.WriteString(s + "\r\n"); _ = rw.Flush() }
		reply("220 fake ESMTP")
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				out <- seen
				return
			}
			cmd := strings.ToUpper(strings.Fields(strings.TrimSpace(line) + " x")[0])
			seen = append(seen, cmd)
			switch cmd {
			case "EHLO":
				reply("250-fake")
				reply("250 AUTH PLAIN")
			case "QUIT":
				reply("221 bye")
				out <- seen
				return
			default:
				reply("250 ok")
			}
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, out
}

func TestMailServiceRequiresSTARTTLS(t *testing.T) {
	host, port, commands := fakeSMTP(t)
	svc := NewMailService(&config.Config{
		SMTPHost: host, SMTPPort: port, SMTPFrom: "alerts@example.test", SMTPTo: "ops@example.test",
		SMTPUser: "user", SMTPPass: "secret",
	})
	err := svc.SendAlert("subject", "operational details")
	require.Error(t, err)
	require.Contains(t, err.Error(), "STARTTLS")
	seen := <-commands
	for _, cmd := range seen {
		require.NotContains(t, []string{"AUTH", "MAIL", "RCPT", "DATA"}, cmd, "nothing may be sent without TLS")
	}
}

func TestMailServiceRejectsUnknownTLSMode(t *testing.T) {
	svc := NewMailService(&config.Config{SMTPHost: "127.0.0.1", SMTPPort: 1, SMTPTLS: "maybe"})
	err := svc.SendAlert("subject", "body")
	require.Error(t, err)
	require.Contains(t, err.Error(), strconv.Quote("maybe"))
}
