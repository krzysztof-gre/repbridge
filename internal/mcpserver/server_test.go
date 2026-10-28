package mcpserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/cli"
	"github.com/krzysztof-gre/repbridge/internal/mcpserver"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixture(t *testing.T, transport roundTrip, override ...string) (*sdk.ClientSession, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "key")
	vault := filepath.Join(dir, "credentials.enc")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPBRIDGE_TOKEN_FILE", vault)
	t.Setenv("REPBRIDGE_VAULT_KEY_FILE", keyFile)
	path, err := filepath.Abs("../policy/testdata/activity-history.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(override) > 0 {
		path = filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, []byte(override[0]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REPBRIDGE_POLICY_FILE", path)
	store, err := auth.ConfiguredTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(24 * time.Hour).Unix()})
	access := "fixture." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	if err := store.Save(context.Background(), &garmin.Credentials{AccessToken: access, RefreshToken: "fixture-refresh", ClientID: "fixture-client"}); err != nil {
		t.Fatal(err)
	}
	old := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = old })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	server, cleanup, err := mcpserver.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ct, st := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "offline-fixture", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, vault
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestPolicyAcrossDiscoveryNativeResultsAndWrites(t *testing.T) {
	var calls, posts atomic.Int32
	var successful atomic.Bool
	cs, vault := fixture(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method == "POST" {
			posts.Add(1)
			if successful.Load() {
				return response(200, `{"workoutId":55,"workoutName":"AI: Fixture","ownerId":999,"private":"must-not-escape"}`), nil
			}
			return response(500, `{"private":"must-not-escape"}`), nil
		}
		return response(200, `{"activityId":12,"activityName":"ride","startTimeGMT":"2026-10-20 12:00:00","distance":30,"duration":20,"activityType":{"typeKey":"cycling"},"ownerId":999,"startLatitude":51,"description":"must-not-escape","averageHR":140}`), nil
	})
	ctx := context.Background()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tool := range tools.Tools {
		seen[tool.Name] = true
	}
	if !seen["get_activity"] || !seen["create_workout"] || seen["update_activity"] || seen["delete_workout"] {
		t.Fatalf("unexpected tools: %v", seen)
	}
	result, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}})
	if err != nil || result.IsError {
		t.Fatalf("get: %v %v", err, result)
	}
	encoded, _ := json.Marshal(result)
	for _, word := range []string{"ownerId", "startLatitude", "averageHR", "must-not-escape"} {
		if !bytes.Contains(encoded, []byte(word)) {
			t.Fatalf("owner-authorized full activity field missing: %s", word)
		}
	}
	if !bytes.Contains(encoded, []byte("cycling")) {
		t.Fatal("selected nested field missing")
	}
	workoutBytes, err := os.ReadFile("../../examples/strength-workout.json")
	if err != nil {
		t.Fatal(err)
	}
	var workout map[string]any
	if err := json.Unmarshal(workoutBytes, &workout); err != nil {
		t.Fatal(err)
	}
	workout["workoutName"] = "No prefix"
	before := calls.Load()
	result, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_workout", Arguments: map[string]any{"workout": workout}})
	if err != nil || !result.IsError || calls.Load() != before {
		t.Fatalf("prefix denial did not happen before network: err=%v calls=%d", err, calls.Load())
	}
	workout["workoutName"] = "AI: Fixture"
	result, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_workout", Arguments: map[string]any{"workout": workout}})
	if err != nil || !result.IsError || posts.Load() != 1 {
		t.Fatalf("write must execute once without 5xx retry: err=%v posts=%d result=%v", err, posts.Load(), result)
	}
	encoded, _ = json.Marshal(result)
	if bytes.Contains(encoded, []byte("must-not-escape")) {
		t.Fatal("upstream error body escaped")
	}
	successful.Store(true)
	result, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_workout", Arguments: map[string]any{"workout": workout}})
	if err != nil || result.IsError {
		t.Fatalf("fixture create failed: %v %v", err, result)
	}
	encoded, _ = json.Marshal(result)
	if bytes.Contains(encoded, []byte("ownerId")) || bytes.Contains(encoded, []byte("must-not-escape")) || !bytes.Contains(encoded, []byte("workoutId")) {
		t.Fatalf("write response projection failed: %s", encoded)
	}
	before = calls.Load()
	result, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_workout", Arguments: json.RawMessage(`{"workout":{"workoutName":"AI: Fixture","workoutName":"wrong"}}`)})
	if err != nil || !result.IsError || calls.Load() != before {
		t.Fatal("duplicate argument keys were not rejected before network")
	}
	if err := cli.Run(ctx, []string{"auth", "logout"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	before = calls.Load()
	result, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}})
	if err != nil || !result.IsError || calls.Load() != before {
		t.Fatal("running server kept authority after logout")
	}
	if _, err := os.Stat(vault); !os.IsNotExist(err) {
		t.Fatal("logout vault was recreated")
	}
}

func TestCancellationReachesNativeHTTP(t *testing.T) {
	entered := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach fixture")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach native HTTP")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("caller did not complete")
	}
}

func TestCancelledQueuedWriteCannotExecute(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var posts atomic.Int32
	cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts.Add(1)
			return response(200, `{"workoutId":1}`), nil
		}
		entered <- struct{}{}
		select {
		case <-release:
			return response(200, `{"activityId":12,"startTimeGMT":"2026-10-20 12:00:00"}`), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not acquire operation lock")
	}
	workoutBytes, err := os.ReadFile("../../examples/strength-workout.json")
	if err != nil {
		t.Fatal(err)
	}
	var workout map[string]any
	if err := json.Unmarshal(workoutBytes, &workout); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_workout", Arguments: map[string]any{"workout": workout}})
	close(release)
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not finish")
	}
	// A following read crosses the same operation lock after cancellation.
	barrier, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if result, err := cs.CallTool(barrier, &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}}); err != nil || result.IsError {
		t.Fatalf("following read failed: %v %v", err, result)
	}
	if posts.Load() != 0 {
		t.Fatal("cancelled queued write executed")
	}
}

func TestNewCallUsesReplacedAccount(t *testing.T) {
	var authorization string
	cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
		authorization = r.Header.Get("Authorization")
		return response(200, `{"activityId":12,"startTimeGMT":"2026-10-20 12:00:00"}`), nil
	})
	call := func() {
		t.Helper()
		r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "get_activity", Arguments: map[string]any{"activity_id": 12}})
		if err != nil || r.IsError {
			t.Fatalf("get failed: %v %v", err, r)
		}
	}
	call()
	previous := authorization
	store, err := auth.ConfiguredTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	creds.AccessToken = strings.Replace(creds.AccessToken, "fixture.", "replaced-account.", 1)
	err = auth.WithOperation(context.Background(), func() error { return store.Save(context.Background(), creds) })
	if err != nil {
		t.Fatal(err)
	}
	call()
	if authorization == previous {
		t.Fatal("server used the previous account token")
	}
}

func TestMissingPolicyFailsBeforeDiscovery(t *testing.T) {
	t.Setenv("REPBRIDGE_POLICY_FILE", filepath.Join(t.TempDir(), "missing.json"))
	if _, _, err := mcpserver.New(context.Background()); err == nil {
		t.Fatal("server accepted a missing policy")
	}
}

func TestEveryClassifiedToolUsesTheGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*","Fields":["*"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPBRIDGE_POLICY_FILE", path)
	// This enumerates the entire catalogue under race instrumentation. Leave
	// room for a shared Docker runner compiling other release architectures.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server, cleanup, err := mcpserver.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ct, st := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "catalogue-fixture", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for cursor := tools.NextCursor; cursor != ""; {
		page, err := cs.ListTools(ctx, &sdk.ListToolsParams{Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		tools.Tools = append(tools.Tools, page.Tools...)
		cursor = page.NextCursor
	}
	if len(tools.Tools) != len(policy.Actions()) {
		t.Fatalf("catalogue=%d tools=%d", len(policy.Actions()), len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		a, known := policy.LookupTool(tool.Name)
		if !known || tool.Annotations == nil || tool.Annotations.ReadOnlyHint == a.Write || !strings.Contains(tool.Description, "Policy action: "+a.Name) {
			t.Errorf("unclassified or unguarded tool %s", tool.Name)
		}
	}
}

func TestExistingWorkoutConditionsUseFetchedName(t *testing.T) {
	custom := `{"Version":"2026-10-20","Statement":[{"Effect":"Allow","Action":["garmin:delete_workout","garmin:schedule_workout"],"Resource":"*","Fields":["*"],"Condition":{"StringLike":{"garmin:WorkoutName":["AI: *"]}}}]}`
	for _, tool := range []string{"delete_workout", "schedule_workout"} {
		for _, allowed := range []bool{false, true} {
			t.Run(tool+map[bool]string{false: "_denied", true: "_allowed"}[allowed], func(t *testing.T) {
				var lookups, writes atomic.Int32
				cs, _ := fixture(t, func(r *http.Request) (*http.Response, error) {
					if r.Method == "GET" {
						lookups.Add(1)
						name := "Owner workout"
						if allowed {
							name = "AI: Fixture"
						}
						b, _ := json.Marshal(map[string]any{"workoutId": 12, "workoutName": name})
						return response(200, string(b)), nil
					}
					writes.Add(1)
					if r.Method == "DELETE" {
						return response(204, ""), nil
					}
					return response(200, `{"workoutId":12}`), nil
				}, custom)
				result, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: map[string]any{"workout_id": 12}})
				if err != nil || result.IsError == allowed {
					t.Fatalf("condition result: %v %v", err, result)
				}
				want := int32(0)
				if allowed {
					want = 1
				}
				if lookups.Load() != 1 || writes.Load() != want {
					t.Fatalf("lookups=%d writes=%d", lookups.Load(), writes.Load())
				}
			})
		}
	}
}
