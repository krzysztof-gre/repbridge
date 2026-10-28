package mcpserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/policy"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	base http.RoundTripper
	key  string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return b.base.RoundTrip(r)
}
func TestHTTPMCPTransportUsesSamePolicyGuard(t *testing.T) {
	p, err := policy.Parse([]byte(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["repbridge:search_exercises"],"Resource":"*","Fields":["/total"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, cleanup, err := newWithPolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	key := bytes.Repeat([]byte{21}, 32)
	ts := httptest.NewServer(httpHandler(server, key))
	defer ts.Close()
	response, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("health endpoint failed")
	}
	response, err = http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("unauthenticated MCP request accepted")
	}
	client := &http.Client{Transport: bearerTransport{http.DefaultTransport, hex.EncodeToString(key)}}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "http-fixture", Version: "1"}, nil).Connect(ctx, &sdk.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	list, err := session.ListTools(ctx, nil)
	if err != nil || len(list.Tools) != 1 || list.Tools[0].Name != "search_exercises" {
		t.Fatalf("discovery leaked %v %v", list, err)
	}
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "search_exercises", Arguments: map[string]any{"query": "pull"}})
	if err != nil || result.IsError {
		t.Fatalf("call %v %v", result, err)
	}
	if len(result.Content) != 1 || strings.Contains(result.Content[0].(*sdk.TextContent).Text, "exercises") {
		t.Fatal("HTTP result bypassed projection")
	}
	if _, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_profile"}); err == nil {
		t.Fatal("guessed tool bypassed discovery")
	}
	if err := serveHTTP(ctx, "invalid:port", http.NotFoundHandler()); err == nil {
		t.Fatal("invalid listen address accepted")
	}
}
