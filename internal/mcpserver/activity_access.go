package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/jsondoc"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

// All activity reads, including the exercise-set adapter, use this guard.
// Metadata lookup and the requested read share the credential operation lock.
func invokeActivity(ctx context.Context, p *policy.Policy, a policy.Action, args map[string]any, read func(*garmin.Client) (any, error)) (any, error) {
	var output any
	err := auth.WithClient(ctx, func(client *garmin.Client) error {
		needsTime := p.NeedsActivityStartTime(a.Name)
		if a.ActivityCollection && needsTime {
			// install evaluates and projects each returned record individually.
			var err error
			output, err = read(client)
			return err
		}
		if a.ActivityResult && needsTime {
			value, err := read(client)
			if err != nil {
				return err
			}
			activity, ok := value.(*garmin.Activity)
			if !ok {
				return errDenied
			}
			attrs, err := activityAttributes(activity)
			if err != nil {
				return errDenied
			}
			d := p.Evaluate(a.Name, attrs)
			if !d.Allowed {
				return errDenied
			}
			output = authorizedResult{value: value, decision: d}
			return nil
		}
		var activity *garmin.Activity
		var attrs map[string]string
		if needsTime {
			id, err := integer(args["activity_id"])
			if err != nil {
				return errDenied
			}
			activity, err = client.Activities.Get(ctx, id)
			if err != nil {
				return err
			}
			if activity == nil || activity.ActivityID != id {
				return errDenied
			}
			attrs, err = activityAttributes(activity)
			if err != nil {
				return errDenied
			}
		}
		d := p.Evaluate(a.Name, attrs)
		if !d.Allowed {
			return errDenied
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reuse the authorization lookup for get_activity; never fetch twice.
		var value any = activity
		if activity == nil || a.Tool != "get_activity" {
			var err error
			value, err = read(client)
			if err != nil {
				return err
			}
		}
		output = authorizedResult{value: value, decision: d}
		return nil
	})
	return output, err
}

func activityAttributes(activity *garmin.Activity) (map[string]string, error) {
	if activity == nil || activity.ActivityID <= 0 {
		return nil, errDenied
	}
	timestamps := []string{}
	if activity.StartTimeGMT != "" {
		timestamps = append(timestamps, activity.StartTimeGMT)
	}
	if len(activity.SummaryDTO) > 0 && string(activity.SummaryDTO) != "null" {
		value, err := jsondoc.Decode(activity.SummaryDTO, 1<<20)
		summary, ok := value.(map[string]any)
		if err != nil || !ok {
			return nil, errDenied
		}
		if value, present := summary["startTimeGMT"]; present {
			stamp, ok := value.(string)
			if !ok || stamp == "" {
				return nil, errDenied
			}
			timestamps = append(timestamps, stamp)
		}
	}
	if len(timestamps) == 0 {
		return nil, errDenied
	}
	var start time.Time
	for i, stamp := range timestamps {
		// Reuse upstream's UTC parser, including Garmin's naive UTC formats.
		metadata := garmin.Activity{StartTimeGMT: stamp}
		parsed, err := metadata.StartGMT()
		if err != nil || (i > 0 && !start.Equal(parsed)) {
			return nil, errDenied
		}
		start = parsed
	}
	return map[string]string{policy.ActivityStartTimeKey: start.UTC().Format(time.RFC3339Nano)}, nil
}

// Filter records before field projection. Each record gets its own decision,
// so conditional grants cannot widen fields disclosed for another activity.
func projectActivityPage(p *policy.Policy, a policy.Action, document any) (any, error) {
	if document == nil {
		return []any{}, nil
	}
	page, ok := document.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid activity page")
	}
	permitted := []any{}
	for _, record := range page {
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		var activity garmin.Activity
		if json.Unmarshal(encoded, &activity) != nil {
			continue
		}
		attrs, err := activityAttributes(&activity)
		if err != nil {
			continue
		}
		d := p.Evaluate(a.Name, attrs)
		if !d.Allowed {
			continue
		}
		filtered, err := d.Project(record)
		if err != nil {
			return nil, err
		}
		permitted = append(permitted, filtered)
	}
	return permitted, nil
}
