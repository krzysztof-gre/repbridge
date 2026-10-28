package mcpserver

import (
	"context"
	"io"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ndeloof/go-garmin/pkg/garmin"
	upstream "github.com/ndeloof/go-garmin/pkg/mcp"
)

// Each invocation owns its upstream server and context. Upstream's ignored
// cancellation notifications cannot keep an operation alive after this context.
func connectUpstream(ctx context.Context, client *garmin.Client) (*sdk.ClientSession, func(), error) {
	rr, rw := io.Pipe()
	sr, sw := io.Pipe()
	runCtx, cancel := context.WithCancel(ctx)
	closePipes := func() { rr.Close(); rw.Close(); sr.Close(); sw.Close() }
	stop := context.AfterFunc(runCtx, closePipes)
	cleanup := func() { cancel(); stop(); closePipes() }
	go func() { _ = upstream.NewServer(client).ServeStdio(runCtx, rr, sw); sw.Close() }()
	c := sdk.NewClient(&sdk.Implementation{Name: "repbridge-upstream-adapter", Version: "0.3.0"}, nil)
	s, err := c.Connect(runCtx, &sdk.IOTransport{Reader: sr, Writer: rw, MaxLineLength: 16 << 20}, nil)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return s, func() { cleanup(); s.Close() }, nil
}
