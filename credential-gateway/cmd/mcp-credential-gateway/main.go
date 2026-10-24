// Command mcp-credential-gateway runs the credential gateway as its own service.
// It reads its configuration from the file named by MCP_GATEWAY_CONFIG (or the
// -config flag), serves until it receives SIGINT or SIGTERM, and then drains.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("mcp-credential-gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", os.Getenv("MCP_GATEWAY_CONFIG"), "gateway configuration file (default $MCP_GATEWAY_CONFIG)")
	flag.Parse()
	if *path == "" {
		return errors.New("set MCP_GATEWAY_CONFIG or pass -config")
	}
	gateway, err := credentialgateway.Open(*path, version)
	if err != nil {
		return errors.New("gateway initialization failed; verify the configuration, key and session binding files")
	}
	srv := &http.Server{Addr: gateway.ListenAddr(), Handler: gateway.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return errors.New("the configured listener could not be opened")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(listener) }()
	slog.Info("mcp-credential-gateway listening", "addr", srv.Addr, "version", version)
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
