package main

import (
	"github.com/Agent-Hellboy/mcp-auth/auth-server/application"
	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	auth, closeStore, err := application.Open(server.ConfigFromEnv())
	if err != nil {
		slog.Error("server initialization failed", "error", err)
		os.Exit(1)
	}
	defer closeStore()
	slog.Info("mcp auth server listening", "addr", auth.Config.ListenAddr, "issuer", auth.Config.Issuer)
	if err := http.ListenAndServe(auth.Config.ListenAddr, auth.Handler()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
