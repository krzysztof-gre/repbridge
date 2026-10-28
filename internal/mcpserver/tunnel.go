package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/krzysztof-gre/repbridge/internal/secretfile"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	tunnelclient "github.com/openai/tunnel-client"
	tunnelconfig "github.com/openai/tunnel-client/pkg/config"
)

func gatewayConfig(tunnelID, keyPath string) (tunnelclient.Config, error) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelconfig.ValidateTunnelID(tunnelID) != nil {
		return tunnelclient.Config{}, fmt.Errorf("set REPBRIDGE_OPENAI_TUNNEL_ID to the complete tunnel ID from OpenAI Platform")
	}
	data, err := secretfile.Read(keyPath, 4096)
	if err != nil {
		return tunnelclient.Config{}, fmt.Errorf("OpenAI runtime key must be in a private regular file outside the repository")
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return tunnelclient.Config{}, fmt.Errorf("OpenAI runtime key file is empty or unreadable")
	}
	for _, r := range key {
		if r <= ' ' || r > '~' {
			return tunnelclient.Config{}, fmt.Errorf("OpenAI runtime key must be a single key without whitespace")
		}
	}
	return tunnelclient.Config{TunnelID: tunnelID, APIKey: key, MaxInFlightRequests: 4, LogLevel: slog.LevelError, LogWriter: io.Discard}, nil
}

// CheckGateway validates mounted configuration offline, without returning keys
// or making an OpenAI/Garmin request. Only a real poll verifies the tunnel.
func CheckGateway(ctx context.Context, out io.Writer) error {
	cfg, err := gatewayConfig(os.Getenv("REPBRIDGE_OPENAI_TUNNEL_ID"), environment("REPBRIDGE_OPENAI_API_KEY_FILE", "/run/secrets/openai-runtime-key"))
	if err != nil {
		return err
	}
	if _, err := policy.Load(policy.ConfiguredPath()); err != nil {
		return err
	}
	status, err := auth.Session(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"tunnelId": cfg.TunnelID, "configurationValid": true, "connectionVerified": false, "garmin": status})
}

// runTunnel uses the official embedded client with an in-memory transport.
// Runtime keys remain in a separately mounted file, never in model context.
func runTunnel(ctx context.Context, server *sdk.Server, tunnelID, keyPath string, out io.Writer) error {
	cfg, err := gatewayConfig(tunnelID, keyPath)
	if err != nil {
		return err
	}
	serverSide, tunnelSide := sdk.NewInMemoryTransports()
	// SDK logs may contain upstream diagnostics; expose fixed local messages only.
	client, err := tunnelclient.New(cfg, tunnelSide)
	if err != nil {
		return fmt.Errorf("configure OpenAI tunnel: check the tunnel ID and runtime key")
	}
	runCtx, cancel := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); serverDone <- server.Run(runCtx, serverSide) }()
	go func() { defer workers.Done(); clientDone <- client.Run(runCtx) }()
	defer func() { cancel(); workers.Wait() }()
	_, _ = fmt.Fprintln(out, "OpenAI gateway starting; waiting for the first successful tunnel poll.")
	startup := time.NewTimer(90 * time.Second)
	defer startup.Stop()
	ready := client.Ready()
	var startupTimeout <-chan time.Time = startup.C
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-serverDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("OpenAI gateway MCP server stopped; restart the gateway")
		case <-clientDone:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("OpenAI gateway tunnel stopped; check runtime permissions and configuration")
		case <-ready:
			_, _ = fmt.Fprintln(out, "OpenAI gateway connected: the first authenticated tunnel poll succeeded. Add this tunnel in ChatGPT Plugins; a ChatGPT tool call confirms the complete connection.")
			ready = nil
			startup.Stop()
			startupTimeout = nil
		case <-startupTimeout:
			return fmt.Errorf("OpenAI gateway did not connect within 90 seconds; check network access, tunnel ID and runtime key Tunnels Read + Use permissions")
		}
	}
}
