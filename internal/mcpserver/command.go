package mcpserver

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/access"
	"github.com/krzysztof-gre/repbridge/internal/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	flags.SetOutput(errOut)
	transport := flags.String("transport", "stdio", "stdio, http or tunnel")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("usage: repbridge mcp [--transport stdio|http|tunnel]")
	}
	if *transport != "stdio" && *transport != "http" && *transport != "tunnel" {
		return fmt.Errorf("unsupported MCP transport")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server, cleanup, err := New(runCtx)
	if err != nil {
		return err
	}
	defer cleanup()
	go auth.MaintainSession(runCtx, errOut)
	switch *transport {
	case "stdio":
		return server.Run(runCtx, &sdk.StdioTransport{})
	case "tunnel":
		return runTunnel(runCtx, server, os.Getenv("REPBRIDGE_OPENAI_TUNNEL_ID"), environment("REPBRIDGE_OPENAI_API_KEY_FILE", "/run/secrets/openai-runtime-key"), errOut)
	case "http":
		key, err := access.ReadKey(environment("REPBRIDGE_MCP_KEY_FILE", "/run/secrets/repbridge-mcp-key"))
		if err != nil {
			return err
		}
		mux := httpHandler(server, key)
		address := environment("REPBRIDGE_MCP_LISTEN_ADDRESS", "0.0.0.0:8080")
		_, _ = fmt.Fprintf(errOut, "Private MCP HTTP listening on %s; bearer authentication required\n", address)
		return serveHTTP(runCtx, address, mux)
	}
	return nil
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func serveHTTP(ctx context.Context, address string, handler http.Handler) error {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	err := server.ListenAndServe()
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// httpHandler is shared by production HTTP startup and transport integration tests.
func httpHandler(server *sdk.Server, key []byte) http.Handler {
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20})
	mux := http.NewServeMux()
	mux.Handle("/mcp", access.Bearer(key, handler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	return mux
}
