package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/krzysztof-gre/repbridge/internal/policy"
)

func TestDefaultPolicyDecisionsAndProjection(t *testing.T) {
	p, err := policy.Load("testdata/activity-history.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action, name string
		allowed      bool
	}{
		{"garmin:list_activities", "", true}, {"garmin:update_activity", "", false},
		{"garmin:create_workout", "AI: Pull-ups", true}, {"garmin:create_workout", "Pull-ups", false},
		{"garmin:create_workout", "ai: Pull-ups", false}, {"garmin:create_workout", " AI: Pull-ups", false},
		{"garmin:delete_workout", "AI: Pull-ups", false}, {"garmin:unknown", "", false},
	} {
		d := p.Evaluate(tc.action, map[string]string{"garmin:WorkoutName": tc.name, policy.ActivityStartTimeKey: "2026-10-20T12:00:00Z"})
		if d.Allowed != tc.allowed {
			t.Errorf("%s %q: allowed=%v", tc.action, tc.name, d.Allowed)
		}
	}
	var raw any
	if err := json.Unmarshal([]byte(`[{"activityId":12,"activityName":"ride","activityType":{"typeKey":"cycling","secret":"private"},"distance":30,"ownerId":999,"startLatitude":51,"averageHR":140}]`), &raw); err != nil {
		t.Fatal(err)
	}
	// Field projection remains available when an owner chooses a narrower grant.
	selection := policy.Decision{Allowed: true, Fields: []string{"/activityId", "/activityName", "/activityType/typeKey", "/distance"}}
	filtered, err := selection.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(filtered)
	for _, forbidden := range []string{"private", "secret", "ownerId", "startLatitude", "averageHR"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("field escaped: %s", forbidden)
		}
	}
	if !strings.Contains(string(encoded), `"typeKey":"cycling"`) {
		t.Fatal("allowed nested field missing")
	}
}

func TestDenyPrecedenceAndStrictParsing(t *testing.T) {
	base := `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:*"],"Resource":"*","Fields":["*"]},{"Effect":"Deny","Action":["garmin:update_activity"],"Resource":"*"}]}`
	p, err := policy.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if p.Evaluate("garmin:update_activity", nil).Allowed || p.Possible("garmin:update_activity") {
		t.Fatal("explicit deny lost")
	}
	for _, bad := range []string{
		strings.Replace(base, `"Version":"2026-10-20"`, `"Version":"2026-10-20","Version":"2026-10-20"`, 1),
		strings.Replace(base, `"Effect":"Allow"`, `"effect":"Allow"`, 1),
		strings.Replace(base, `"Fields":["*"]`, `"Fields":[]`, 1),
		strings.Replace(base, `"garmin:*"`, `"garmin:typo"`, 1),
		strings.Replace(base, `"Resource":"*"`, `"Resource":"arn:unimplemented"`, 1),
		strings.Replace(base, `"Fields":["*"]`, `"Fields":["/bad~2path"]`, 1),
	} {
		if _, err := policy.Parse([]byte(bad)); err == nil {
			t.Errorf("invalid policy accepted: %s", bad)
		}
	}
}

func TestNestedArraysAndParentDisclosure(t *testing.T) {
	d := policy.Decision{Allowed: true, Fields: []string{"/laps/*/distance", "/a~1b/~0value"}}
	input := map[string]any{"laps": []any{map[string]any{"distance": 12, "gps": "hidden"}}, "a/b": map[string]any{"~value": 3, "other": "hidden"}, "owner": "hidden"}
	got, err := d.Project(input)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if string(b) != `{"a/b":{"~value":3},"laps":[{"distance":12}]}` {
		t.Fatalf("projection=%s", b)
	}
	d.Fields = []string{"/laps"}
	got, err = d.Project(input)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(got)
	if !strings.Contains(string(b), "gps") {
		t.Fatal("explicit parent disclosure lost")
	}
}

func TestMissingConditionsAndConditionalDeny(t *testing.T) {
	p, err := policy.Parse([]byte(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:create_workout"],"Resource":"*","Fields":["/workoutId"],"Condition":{"StringLike":{"garmin:WorkoutName":["AI: *"]}}},{"Effect":"Deny","Action":["garmin:create_workout"],"Resource":"*","Condition":{"StringEquals":{"garmin:WorkoutName":["AI: forbidden"]}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Evaluate("garmin:create_workout", nil).Allowed {
		t.Fatal("missing condition attribute granted access")
	}
	if d := p.Evaluate("garmin:create_workout", map[string]string{"garmin:WorkoutName": "AI: forbidden"}); d.Allowed || d.Reason != "explicit_deny" {
		t.Fatal("conditional deny lost")
	}
}
