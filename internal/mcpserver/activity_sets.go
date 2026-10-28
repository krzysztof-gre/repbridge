package mcpserver

import (
	"context"

	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

// The upstream client supports ExerciseSets but its MCP catalogue does not yet
// expose that read. This adapter uses our normal policy/result projection path.
func readExerciseSets(ctx context.Context, p *policy.Policy, args map[string]any) (any, error) {
	id, err := integer(args["activity_id"])
	if err != nil {
		return nil, err
	}
	a, _ := policy.LookupTool("get_activity_exercise_sets")
	return invokeActivity(ctx, p, a, args, func(client *garmin.Client) (any, error) {
		return client.Activities.ExerciseSets(ctx, id)
	})
}
