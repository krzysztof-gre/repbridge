package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	validator "github.com/google/jsonschema-go/jsonschema"
	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/jsondoc"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

var errInvalidWorkout = fmt.Errorf("invalid native workout")

func nativeWorkoutName(workout map[string]any) (string, error) {
	name, ok := workout["workoutName"].(string)
	if !ok || name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return "", errDenied
	}
	return name, nil
}

func validateWorkout(workout map[string]any, schema *validator.Resolved) error {
	applyWorkoutDefaults(workout)
	encoded, err := json.Marshal(workout)
	if err != nil {
		return errInvalidWorkout
	}
	var check any
	if json.Unmarshal(encoded, &check) != nil || schema.Validate(check) != nil {
		return errInvalidWorkout
	}
	return nil
}

// Call under auth.WithClient so lookup and mutation share the operation lock.
func existingWorkoutName(ctx context.Context, client *garmin.Client, id int64) (string, error) {
	raw, err := client.Workouts.Get(ctx, id)
	if err != nil {
		return "", err
	}
	value, err := jsondoc.Decode(raw, 1<<20)
	if err != nil {
		return "", err
	}
	workout, ok := value.(map[string]any)
	if !ok {
		return "", errDenied
	}
	fetchedID, err := integer(workout["workoutId"])
	if err != nil || fetchedID != id {
		return "", errDenied
	}
	return nativeWorkoutName(workout)
}

// Upstream exposes Update in its client but not its MCP catalogue. Reuse its
// full replacement method and our normal policy/projection/credential guards.
func updateWorkout(ctx context.Context, p *policy.Policy, args map[string]any, schema *validator.Resolved) (any, error) {
	const action = "garmin:update_workout"
	id, err := integer(args["workout_id"])
	if err != nil {
		return nil, errInvalidWorkout
	}
	workout, ok := args["workout"].(map[string]any)
	if !ok {
		return nil, errInvalidWorkout
	}
	name, err := nativeWorkoutName(workout)
	if err != nil {
		return nil, err
	}
	d := p.Evaluate(action, map[string]string{"garmin:WorkoutName": name})
	if !d.Allowed {
		return nil, errDenied
	}
	if err := validateWorkout(workout, schema); err != nil {
		return nil, err
	}
	if embedded, present := workout["workoutId"]; present {
		embeddedID, err := integer(embedded)
		if err != nil || embeddedID != id {
			return nil, errInvalidWorkout
		}
	}
	var receipt any = map[string]any{"workoutId": id, "workoutName": name}
	err = auth.WithClient(ctx, func(client *garmin.Client) error {
		if p.NeedsWorkoutName(action) {
			existing, err := existingWorkoutName(ctx, client, id)
			if err != nil {
				return err
			}
			before := p.Evaluate(action, map[string]string{"garmin:WorkoutName": existing})
			if !before.Allowed {
				return errDenied
			}
			// Applying both projections prevents a rename from widening disclosure.
			receipt, err = before.Project(receipt)
			if err != nil {
				return errDenied
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return client.Workouts.Update(ctx, id, workout)
	})
	return authorizedResult{value: receipt, decision: d}, err
}

// pushWorkout reuses upstream delivery, with a trusted name lookup and device
// ownership check under the same account lock as the mutation.
func pushWorkout(ctx context.Context, p *policy.Policy, args map[string]any) (any, error) {
	const action = "garmin:push_workout_to_device"
	id, err := integer(args["workout_id"])
	if err != nil {
		return nil, errDenied
	}
	deviceID, err := integer(args["device_id"])
	if err != nil {
		return nil, errDenied
	}
	var output any
	err = auth.WithClient(ctx, func(client *garmin.Client) error {
		name, err := existingWorkoutName(ctx, client, id)
		if err != nil {
			return err
		}
		d := p.Evaluate(action, map[string]string{"garmin:WorkoutName": name})
		if !d.Allowed {
			return errDenied
		}
		devices, err := client.Devices.List(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, device := range devices {
			if device.DeviceID == deviceID {
				found = true
				break
			}
		}
		if !found {
			return errDenied
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := client.Workouts.PushToDevice(ctx, id, deviceID); err != nil {
			return err
		}
		output = authorizedResult{value: map[string]any{"workoutId": id, "deviceId": deviceID, "queued": true}, decision: d}
		return nil
	})
	return output, err
}
