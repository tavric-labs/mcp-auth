package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/application"
	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
	combinedserver "github.com/Agent-Hellboy/mcp-auth/combined-server"
	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("mcp-auth stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	auth, closeStore, err := application.Open(server.ConfigFromEnv())
	if err != nil {
		return err
	}
	defer closeStore()
	servers := []*http.Server{{Addr: auth.Config.ListenAddr, Handler: auth.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}}
	if path := os.Getenv("MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG"); path != "" {
		gateway, err := credentialgateway.Open(path, version)
		if err != nil {
			return err
		}
		if err := combinedserver.Attach(auth, gateway); err != nil {
			return err
		}
		servers = append(servers, &http.Server{Addr: gateway.ListenAddr(), Handler: gateway.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second})
	}
	// Bind all listeners before serving. A gateway bind failure cannot leave an
	// OAuth listener issuing grants with a partially started deployment.
	var listeners []net.Listener
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return errors.New("configured HTTP listener could not be opened")
		}
		listeners = append(listeners, ln)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsCh := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errorsCh <- srv.Serve(listeners[i]) }()
	}
	slog.Info("mcp-auth listening", "oauth", auth.Config.ListenAddr, "credential_gateway_enabled", len(servers) > 1)
	select {
	case <-ctx.Done():
	case err = <-errorsCh:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
