package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/garminops"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

func specNamed(t *testing.T, name string) garminops.Spec {
	t.Helper()
	for _, s := range garminops.Specs() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("unknown spec %s", name)
	return garminops.Spec{}
}
func TestEveryClientMethodSignatureAndArgumentDecoder(t *testing.T) {
	for _, s := range garminops.Specs() {
		t.Run(s.Name, func(t *testing.T) {
			method, err := methodValue(&garmin.Client{}, s)
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]any{}
			for i, name := range s.Params {
				typ := method.Type().In(i + 1)
				switch {
				case typ == dateType:
					args[name] = "2026-10-20"
				case typ == readerType:
					args[name] = base64.StdEncoding.EncodeToString([]byte("fixture"))
				case typ == reflect.TypeFor[time.Time]():
					args[name] = "2026-10-20T12:00:00Z"
				case typ.Kind() == reflect.Pointer:
					args[name] = map[string]any{}
				case typ.Kind() == reflect.String:
					args[name] = "fixture"
				case typ.Kind() == reflect.Int64 || typ.Kind() == reflect.Int:
					args[name] = json.Number("1")
				default:
					args[name] = reflect.Zero(typ).Interface()
				}
			}
			if _, ok := args["year"]; ok {
				args["year"] = json.Number("2026")
			}
			if v, err := clientMethodArguments(s, args); err != nil || len(v) != len(s.Params) {
				t.Fatalf("decode %v", err)
			}
			if len(s.Params) > 0 {
				delete(args, s.Params[0])
				typ := method.Type().In(1)
				if typ.Kind() != reflect.Pointer && typ != reflect.TypeFor[time.Time]() {
					if _, err := clientMethodArguments(s, args); err == nil {
						t.Fatal("missing required argument accepted")
					}
				}
			}
			if _, err := clientMethodSchema(s); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestClientArgumentsRejectUnsafeInputs(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"search_activities", map[string]any{"options": map[string]any{"Limit": 101}}},
		{"search_activities", map[string]any{"options": map[string]any{"Start": -1}}},
		{"search_activities", map[string]any{"options": map[string]any{"Start": 10001}}},
		{"search_activities", map[string]any{"options": map[string]any{"Unknown": true}}},
		{"search_activities", map[string]any{"options": map[string]any{"StartDate": "2026-10-20", "EndDate": "2026-10-19"}}},
		{"search_activities", map[string]any{"options": map[string]any{"StartDate": "2026-01-01", "EndDate": "2026-10-20"}}},
	}
	for _, tc := range cases {
		if _, err := clientMethodArguments(specNamed(t, tc.tool), tc.args); err == nil {
			t.Fatalf("unsafe native arguments accepted %v", tc.args)
		}
	}
	spec := specNamed(t, "search_activities")
	values, err := clientMethodArguments(spec, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	limit := values[0].Elem().FieldByName("Limit")
	if limit.Int() != 100 {
		t.Fatal("unbounded default page")
	}
	for _, args := range []map[string]any{{"activity_id": json.Number("0")}, {"limit": json.Number("101")}, {"limit": json.Number("1.5")}, {"start": json.Number("10001")}, {"start_date": "2026-10-20", "end_date": "2026-10-19"}, {"start_date": "invalid"}, {"start_date": "2025-01-01", "end_date": "2026-01-01"}} {
		if validateBounds(args) == nil {
			t.Fatalf("unsafe bounds accepted %v", args)
		}
	}
}
func TestActivityMetadataFailsClosed(t *testing.T) {
	for _, a := range []*garmin.Activity{nil, {}, {ActivityID: 1}, {ActivityID: 1, StartTimeGMT: "invalid"}, {ActivityID: 1, StartTimeGMT: "2026-10-20 12:00:00", SummaryDTO: json.RawMessage(`{"startTimeGMT":"2026-10-19 12:00:00"}`)}, {ActivityID: 1, SummaryDTO: json.RawMessage(`{"startTimeGMT":12}`)}, {ActivityID: 1, SummaryDTO: json.RawMessage(`{"startTimeGMT":"2026-10-20 12:00:00","startTimeGMT":"2026-10-19 12:00:00"}`)}} {
		if _, err := activityAttributes(a); err == nil {
			t.Fatalf("untrusted metadata accepted %+v", a)
		}
	}
	a := &garmin.Activity{ActivityID: 1, StartTimeGMT: "2026-10-20 12:00:00", SummaryDTO: json.RawMessage(`{"startTimeGMT":"2026-10-20T12:00:00Z"}`)}
	got, err := activityAttributes(a)
	if err != nil || got[policy.ActivityStartTimeKey] != "2026-10-20T12:00:00Z" {
		t.Fatalf("UTC metadata %v %v", got, err)
	}
}
func TestPageFilteringProjectsEachGrantIndependently(t *testing.T) {
	p, err := policy.Parse([]byte(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:list_activities"],"Resource":"*","Fields":["/activityId"],"Condition":{"DateGreaterThanEquals":{"garmin:ActivityStartTime":["2026-10-15T00:00:00+02:00"]}}},{"Effect":"Allow","Action":["garmin:list_activities"],"Resource":"*","Fields":["/private"],"Condition":{"DateGreaterThanEquals":{"garmin:ActivityStartTime":["2026-10-20T00:00:00Z"]}}} ]}`))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := policy.LookupTool("list_activities")
	var page any
	_ = json.Unmarshal([]byte(`[{"activityId":1,"startTimeGMT":"2026-10-14T21:59:59Z","private":"old"},{"activityId":2,"startTimeGMT":"2026-10-14T22:00:00Z","private":"middle"},{"activityId":3,"startTimeGMT":"2026-10-20T00:00:00Z","private":"recent"},{"activityId":4,"private":"undated"}]`), &page)
	got, err := projectActivityPage(p, a, page)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if string(b) != `[{"activityId":2},{"activityId":3,"private":"recent"}]` {
		t.Fatalf("filtered page %s", b)
	}
	if _, err := projectActivityPage(p, a, map[string]any{}); err == nil {
		t.Fatal("unexpected envelope accepted")
	}
}
func TestGatewayConfigurationAndCatalogueAreOffline(t *testing.T) {
	key := filepath.Join(t.TempDir(), "runtime.key")
	if err := os.WriteFile(key, []byte("fixture-runtime-key"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "tunnel_0123456789abcdef0123456789abcdef"
	if _, err := gatewayConfig(id, key); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "not-a-tunnel", "tunnel_../escape"} {
		if _, err := gatewayConfig(id, key); err == nil {
			t.Fatal("invalid tunnel accepted")
		}
	}
	if err := os.WriteFile(key, []byte("key\nembedded"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gatewayConfig(id, key); err == nil {
		t.Fatal("multiline key accepted")
	}
	t.Setenv("REPBRIDGE_VAULT_KEY_FILE", "/must-not-read")
	t.Setenv("REPBRIDGE_TOKEN_FILE", "/must-not-read")
	var out bytes.Buffer
	if err := CheckCatalogue(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"classifiedActions":148`) || !strings.Contains(out.String(), `"garminCalls":0`) {
		t.Fatal(out.String())
	}
	for _, args := range [][]string{{"--transport", "bogus"}, {"unexpected"}} {
		if err := Run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}
