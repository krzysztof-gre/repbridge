package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func workoutFixture(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../examples/strength-workout.json")
	if err != nil {
		t.Fatal(err)
	}
	var w map[string]any
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	w["workoutName"] = "AI: Fixture"
	return w
}
func resultJSON(t *testing.T, r *sdk.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestWorkoutUpdateConditionsAndDeliveryOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, existing string
		device         int64
		allowed        bool
	}{
		{"allowed", "AI: Before", 7, true}, {"existing_name_denied", "Owner workout", 7, false}, {"foreign_device", "AI: Before", 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var puts, posts atomic.Int32
			cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == "PUT":
					puts.Add(1)
					body, _ := io.ReadAll(r.Body)
					if !strings.Contains(string(body), `"skipLastRestStep":false`) {
						t.Error("trailing rest default missing")
					}
					return response(204, ""), nil
				case r.Method == "POST":
					posts.Add(1)
					return response(200, `{"private":"hidden"}`), nil
				case strings.Contains(r.URL.Path, "device"):
					return response(200, `[{"deviceId":7}]`), nil
				default:
					return response(200, fmt.Sprintf(`{"workoutId":12,"workoutName":%q}`, tc.existing)), nil
				}
			})
			for _, tool := range []string{"update_workout", "push_workout_to_device"} {
				args := map[string]any{"workout_id": 12}
				want := tc.allowed
				if tool == "update_workout" {
					args["workout"] = workoutFixture(t)
					want = tc.existing != "Owner workout"
				} else {
					args["device_id"] = tc.device
				}
				r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
				if err != nil || r.IsError == want {
					t.Fatalf("%s outcome %v %v", tool, err, r)
				}
				if strings.Contains(resultJSON(t, r), "hidden") {
					t.Fatal("upstream private data escaped")
				}
			}
			if (puts.Load() > 0) != (tc.existing != "Owner workout") || (posts.Load() > 0) != tc.allowed {
				t.Fatal("unauthorized write reached Garmin")
			}
		})
	}
}
func TestWorkoutLookupRejectsMismatchedID(t *testing.T) {
	var writes atomic.Int32
	cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			writes.Add(1)
			return response(200, `{}`), nil
		}
		return response(200, `{"workoutId":99,"workoutName":"AI: Other"}`), nil
	})
	r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "update_workout", Arguments: map[string]any{"workout_id": 12, "workout": workoutFixture(t)}})
	if err != nil || !r.IsError || writes.Load() != 0 {
		t.Fatal("mismatched workout metadata authorized a mutation")
	}
}
func TestClientMethodReadProjectionAndGraphQLErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		error      bool
	}{
		{"get_profile_settings", `{"private":"hidden","selected":1}`, false},
		{"execute_graphql", `{"data":{"selected":1},"errors":[{"message":"hidden"}]}`, true},
		{"execute_graphql", `{"data":{"selected":1}}`, false},
	} {
		t.Run(tc.name+fmt.Sprint(tc.error), func(t *testing.T) {
			custom := fmt.Sprintf(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:%s"],"Resource":"*","Fields":["/selected","/data/selected"]}]}`, tc.name)
			cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) { return response(200, tc.body), nil }, custom)
			args := map[string]any{}
			if tc.name == "execute_graphql" {
				args["request"] = map[string]any{"query": "query { fixture }"}
			}
			r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tc.name, Arguments: args})
			if err != nil || r.IsError != tc.error {
				t.Fatalf("adapter result %v %v", err, r)
			}
			if strings.Contains(resultJSON(t, r), "hidden") {
				t.Fatal("unprojected data disclosed")
			}
		})
	}
}
func TestActivityDetailBeforeCutoffMakesOnlyMetadataRead(t *testing.T) {
	for _, tool := range []string{"get_activity_details", "get_activity_exercise_sets", "get_activity_samples", "get_activity_original_file"} {
		t.Run(tool, func(t *testing.T) {
			var calls atomic.Int32
			cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return response(200, `{"activityId":12,"startTimeGMT":"2026-10-14 21:59:59"}`), nil
			})
			r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: map[string]any{"activity_id": 12}})
			if err != nil || !r.IsError || calls.Load() != 1 {
				t.Fatalf("old activity guard %s %v calls=%d", tool, err, calls.Load())
			}
		})
	}
}
func TestInvalidFileArgumentsCannotAcquireCredentials(t *testing.T) {
	var calls atomic.Int32
	custom := `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"]}]}`
	cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(500, "private"), nil }, custom)
	for _, args := range []map[string]any{{"filename": "../../file.fit", "data_base64": "YWJj"}, {"filename": "file.fit", "data_base64": "not base64"}} {
		r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "upload_activity_file", Arguments: args})
		if err != nil || !r.IsError || calls.Load() != 0 {
			t.Fatal("invalid file input reached Garmin")
		}
	}
}

func TestAdapterChecksForeignProfileDeviceAndGearReferences(t *testing.T) {
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"list_gear", map[string]any{"user_profile_id": 8}},
		{"get_device_settings", map[string]any{"device_id": 8}},
		{"get_gear_stats", map[string]any{"gear_uuid": "foreign"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			var requests atomic.Int32
			custom := `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"]}]}`
			cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				if strings.Contains(r.URL.Path, "socialProfile") {
					return response(200, `{"profileId":7}`), nil
				}
				if strings.Contains(r.URL.Path, "registration") {
					return response(200, `[{"deviceId":7}]`), nil
				}
				if strings.Contains(r.URL.Path, "gear/filterGear") {
					return response(200, `[{"uuid":"owned"}]`), nil
				}
				t.Errorf("foreign resource lookup escaped ownership guard: %s", r.URL.Path)
				return response(500, `{}`), nil
			}, custom)
			r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tc.tool, Arguments: nonNilArguments(tc.args)})
			if err != nil || !r.IsError || requests.Load() == 0 {
				t.Fatalf("ownership enforcement %v %v", err, r)
			}
		})
	}
}

func TestAdapterScalarBinaryAndMultipleResults(t *testing.T) {
	for _, tc := range []struct {
		tool, body, fields, want string
		args                     map[string]any
	}{
		{"count_activities", `{"totalCount":7}`, `["/value"]`, `"value":7`, nil},
		{"get_workout_fit", "fixture-file", `["/encoding","/data"]`, `"data":"Zml4dHVyZS1maWxl"`, map[string]any{"workout_id": 12}},
		{"get_latest_lactate_threshold", `{"selected":1,"private":"hidden"}`, `["/latest/selected","/powerToWeight/selected"]`, `"latest":{"selected":1}`, nil},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			custom := fmt.Sprintf(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:%s"],"Resource":"*","Fields":%s}]}`, tc.tool, tc.fields)
			cs, _ := fixture(t, func(*http.Request) (*http.Response, error) { return response(200, tc.body), nil }, custom)
			r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tc.tool, Arguments: nonNilArguments(tc.args)})
			if err != nil || r.IsError {
				t.Fatalf("adapter failed: %v %s", err, resultJSON(t, r))
			}
			b, _ := json.Marshal(r.StructuredContent)
			if !strings.Contains(string(b), tc.want) || strings.Contains(string(b), "hidden") {
				t.Fatalf("unexpected result %s", b)
			}
		})
	}
}

func nonNilArguments(args map[string]any) map[string]any {
	if args == nil {
		return map[string]any{}
	}
	return args
}
