package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krzysztof-gre/repbridge/internal/policy"
)

func TestStarterGrantsOnlyIntendedWrites(t *testing.T) {
	p, err := policy.Load("../../policies/starter.json")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"garmin:create_workout": true, "garmin:update_workout": true, "garmin:schedule_workout": true, "garmin:push_workout_to_device": true}
	for _, a := range policy.Actions() {
		if a.Write {
			if p.Evaluate(a.Name, map[string]string{"garmin:WorkoutName": "AI: Fixture"}).Allowed != allowed[a.Name] {
				t.Fatalf("unexpected write permission %s", a.Name)
			}
		}
		if a.ActivityStartTime && p.Possible(a.Name) {
			t.Fatalf("starter activity access %s", a.Name)
		}
	}
	// Explicit write Denies must also defeat a future broad Allow.
	p.Statement = append(p.Statement, policy.Statement{Effect: "Allow", Action: []string{"*"}, Resource: "*", Fields: []string{"*"}})
	for _, a := range policy.Actions() {
		if a.Write && !allowed[a.Name] && p.Evaluate(a.Name, nil).Allowed {
			t.Fatalf("broad grant bypassed explicit write Deny %s", a.Name)
		}
	}
}
func TestHistoryBoundaryAndAllDateOperators(t *testing.T) {
	p, err := policy.Load("testdata/activity-history.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range policy.Actions() {
		if !a.ActivityStartTime || !p.Possible(a.Name) {
			continue
		}
		for _, tc := range []struct {
			stamp string
			allow bool
		}{{"2026-10-14T21:59:59.999999999Z", false}, {"2026-10-14T22:00:00Z", true}, {"2026-10-15T00:00:00+02:00", true}, {"", false}, {"not-a-date", false}} {
			if p.Evaluate(a.Name, map[string]string{policy.ActivityStartTimeKey: tc.stamp}).Allowed != tc.allow {
				t.Fatalf("%s boundary=%q", a.Name, tc.stamp)
			}
		}
	}
	for _, op := range []string{"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals"} {
		raw := `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:get_activity"],"Resource":"*","Fields":["/activityId"],"Condition":{"` + op + `":{"garmin:ActivityStartTime":["2026-10-15T00:00:00Z"]}}}]}`
		q, err := policy.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if q.Evaluate("garmin:get_activity", nil).Allowed {
			t.Fatal("missing date granted access")
		}
		for _, stamp := range []string{"2026-10-14T23:59:59Z", "2026-10-15T00:00:00Z", "2026-10-15T00:00:01Z"} {
			got := q.Evaluate("garmin:get_activity", map[string]string{policy.ActivityStartTimeKey: stamp}).Allowed
			equal := stamp == "2026-10-15T00:00:00Z"
			before := stamp == "2026-10-14T23:59:59Z"
			want := map[string]bool{"DateEquals": equal, "DateNotEquals": !equal, "DateLessThan": before, "DateLessThanEquals": before || equal, "DateGreaterThan": !before && !equal, "DateGreaterThanEquals": !before}[op]
			if got != want {
				t.Fatalf("%s %s: allowed=%v want=%v", op, stamp, got, want)
			}
		}
	}
}
func TestPolicyLoadingRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"Version":"2026-10-20","Statement":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, link, filepath.Join(dir, "missing")} {
		if _, err := policy.Load(p); err == nil {
			t.Fatal("unsafe policy path accepted")
		}
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(path); err == nil {
		t.Fatal("writable policy accepted")
	}
	t.Setenv("REPBRIDGE_POLICY_FILE", path)
	if policy.ConfiguredPath() != path {
		t.Fatal("configured path ignored")
	}
}
func FuzzPolicyParse(f *testing.F) {
	for _, s := range []string{`{"Version":"2026-10-20","Statement":[]}`, `{}`, `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"]}]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := policy.Parse([]byte(s))
		if err != nil {
			return
		}
		if p.Evaluate("garmin:unclassified", nil).Allowed {
			t.Fatal("unknown action authorized")
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := policy.Parse(b); err != nil {
			t.Fatal("policy roundtrip failed")
		}
	})
}
func FuzzProjectionDoesNotDiscloseSiblings(f *testing.F) {
	f.Add("owner-secret", "selected")
	f.Fuzz(func(t *testing.T, hidden, selected string) {
		if strings.Contains(hidden, "\x00") {
			return
		}
		d := policy.Decision{Allowed: true, Fields: []string{"/visible"}}
		value, err := d.Project(map[string]any{"visible": selected, "private": hidden})
		if err != nil {
			t.Fatal(err)
		}
		m, ok := value.(map[string]any)
		if !ok || len(m) != 1 || m["visible"] != selected {
			t.Fatal("projection changed selected fields")
		}
		if _, exists := m["private"]; exists {
			t.Fatal("sibling disclosed")
		}
	})
}

func TestUnsupportedPolicyConstructsFailClosed(t *testing.T) {
	for _, s := range []string{
		`{"Version":"2026-10-20","Statement":null}`,
		`{"Version":"2026-10-20","Statement":[],"Principal":"*"}`,
		`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"],"Condition":{"StringLike":{"garmin:WorkoutName":["AI: *"]}}}]}`,
		`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:execute_graphql"],"Resource":"*","Fields":["*"],"Condition":{"DateLessThan":{"garmin:ActivityStartTime":["2026-10-15T00:00:00Z"]}}}]}`,
		`{"Version":"2026-10-20","Statement":[{"Effect":"Deny","Action":["*"],"Resource":"*","Fields":["*"]}]}`,
		`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["repbridge:search_exercises"],"Resource":"*","Fields":["*"],"Condition":{}}]}`,
	} {
		if _, err := policy.Parse([]byte(s)); err == nil {
			t.Fatal("unsupported policy accepted")
		}
	}
}
