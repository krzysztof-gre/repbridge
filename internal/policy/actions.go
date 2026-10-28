package policy

import (
	"sort"

	"github.com/krzysztof-gre/repbridge/internal/garminops"
)

// Action is an explicitly classified capability, never inferred from user input.
type Action struct {
	Name               string `json:"action"`
	Tool               string `json:"tool"`
	Write              bool   `json:"write"`
	Destructive        bool   `json:"destructive"`
	WorkoutName        bool   `json:"workoutNameCondition"`
	ActivityStartTime  bool   `json:"activityStartTimeCondition"`
	ActivityCollection bool   `json:"activityCollection"`
	ActivityResult     bool   `json:"activityResult"`
}

// Catalogue construction happens once. Exported entries are value copies so
// callers cannot mutate the authority used by lookup and evaluation.
var catalogue = buildActions()
var actionsByName = indexActions(false)
var actionsByTool = indexActions(true)

func Actions() []Action { return append([]Action(nil), catalogue...) }

func indexActions(byTool bool) map[string]Action {
	result := make(map[string]Action, len(catalogue))
	for _, action := range catalogue {
		key := action.Name
		if byTool {
			key = action.Tool
		}
		if _, duplicate := result[key]; duplicate {
			panic("duplicate classified capability")
		}
		result[key] = action
	}
	return result
}

func buildActions() []Action {
	reads := []string{
		"get_profile", "get_user_settings", "get_devices", "list_activities",
		"get_activity", "get_activity_details", "get_activity_splits", "get_activity_weather", "get_activity_hr_zones", "get_activity_exercise_sets",
		"get_daily_summary", "get_steps", "get_heart_rate", "get_sleep", "get_stress", "get_hrv", "get_spo2",
		"get_respiration", "get_hydration", "get_body_battery", "get_training_readiness", "get_training_status",
		"get_vo2max", "get_endurance_score", "get_hill_score", "get_fitness_age", "get_race_predictions",
		"get_hr_zones", "get_weight", "get_personal_records", "list_workouts", "get_workout", "list_courses", "get_course",
	}
	writes := []string{"create_activity", "update_activity", "set_hr_zones", "create_workout", "update_workout", "delete_workout", "schedule_workout", "push_workout_to_device", "delete_course", "import_course_gpx", "push_course_to_device"}
	result := make([]Action, 0, len(reads)+len(writes)+5)
	for _, name := range reads {
		a := Action{Name: "garmin:" + name, Tool: name, ActivityCollection: name == "list_activities"}
		switch name {
		case "list_activities", "get_activity", "get_activity_details", "get_activity_splits", "get_activity_weather", "get_activity_hr_zones", "get_activity_exercise_sets":
			a.ActivityStartTime = true
		}
		result = append(result, a)
	}
	for _, name := range writes {
		result = append(result, Action{Name: "garmin:" + name, Tool: name, Write: true,
			Destructive: name == "update_workout" || name == "delete_workout" || name == "delete_course" || name == "update_activity" || name == "set_hr_zones",
			WorkoutName: name == "create_workout" || name == "update_workout" || name == "delete_workout" || name == "schedule_workout" || name == "push_workout_to_device"})
	}
	for _, name := range []string{"get_workout_schema", "search_exercises", "garmin_session_status", "refresh_garmin_session", "get_permissions"} {
		result = append(result, Action{Name: "repbridge:" + name, Tool: name, Write: name == "refresh_garmin_session"})
	}
	for _, spec := range garminops.Specs() {
		result = append(result, Action{Name: "garmin:" + spec.Name, Tool: spec.Name,
			Write: spec.Write, Destructive: spec.Write, WorkoutName: spec.WorkoutName,
			ActivityStartTime: spec.Activity != "", ActivityCollection: spec.Activity == "collection", ActivityResult: spec.Activity == "result"})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func LookupTool(name string) (Action, bool) {
	action, ok := actionsByTool[name]
	return action, ok
}
