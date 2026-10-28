package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/krzysztof-gre/repbridge/internal/policy"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// CheckCatalogue validates every classified tool and schema in an isolated,
// in-memory discovery session. It does not replace the configured owner policy,
// start maintenance, access credentials, or invoke a Garmin operation.
func CheckCatalogue(ctx context.Context, out io.Writer) error {
	p, err := policy.Parse([]byte(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"]}]}`))
	if err != nil {
		return err
	}
	server, cleanup, err := newWithPolicy(ctx, p)
	if err != nil {
		return err
	}
	defer cleanup()
	ct, st := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		return err
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "repbridge-catalogue-check", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return err
	}
	defer cs.Close()
	count := 0
	cursor := ""
	for {
		page, err := cs.ListTools(ctx, &sdk.ListToolsParams{Cursor: cursor})
		if err != nil {
			return err
		}
		count += len(page.Tools)
		for _, tool := range page.Tools {
			a, ok := policy.LookupTool(tool.Name)
			if !ok || tool.Annotations == nil || tool.Annotations.ReadOnlyHint == a.Write {
				return fmt.Errorf("tool classification mismatch")
			}
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if count != len(policy.Actions()) {
		return fmt.Errorf("catalogue and registered tool count differ")
	}
	return json.NewEncoder(out).Encode(map[string]any{"catalogueValid": true, "classifiedActions": count, "credentialsAccessed": false, "garminCalls": 0})
}
