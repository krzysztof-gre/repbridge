package mcpserver

import "github.com/ndeloof/go-garmin/pkg/garmin"

// applyWorkoutDefaults preserves the native payload and explicit preferences.
// Repeat groups keep their existing trailing rest step unless skipping it was
// explicitly requested. It does not invent a rest step or its duration.
func applyWorkoutDefaults(workout map[string]any) {
	segments, _ := workout["workoutSegments"].([]any)
	for _, value := range segments {
		segment, ok := value.(map[string]any)
		if !ok {
			continue
		}
		applyStepDefaults(segment["workoutSteps"])
	}
}

func applyStepDefaults(value any) {
	steps, _ := value.([]any)
	for _, value := range steps {
		step, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if step["type"] == garmin.StepTypeRepeatGroup && step["skipLastRestStep"] == nil {
			step["skipLastRestStep"] = false
		}
		applyStepDefaults(step["workoutSteps"])
	}
}
