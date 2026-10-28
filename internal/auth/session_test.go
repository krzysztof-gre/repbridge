package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

func sessionFixture(t *testing.T, expiry time.Time) *EncryptedTokenStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPBRIDGE_TOKEN_FILE", filepath.Join(dir, "tokens.enc"))
	t.Setenv("REPBRIDGE_VAULT_KEY_FILE", key)
	store, err := NewEncryptedTokenStore(filepath.Join(dir, "tokens.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	if !expiry.IsZero() {
		claims, _ := json.Marshal(map[string]int64{"exp": expiry.Unix()})
		token := "fixture." + base64.RawURLEncoding.EncodeToString(claims) + ".unsigned"
		if err := store.Save(context.Background(), &garmin.Credentials{AccessToken: token, RefreshToken: "fixture-refresh", ClientID: "fixture-client"}); err != nil {
			t.Fatal(err)
		}
	}
	return store
}
func TestSessionStatusNeverDisclosesCredentials(t *testing.T) {
	for _, offset := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			sessionFixture(t, time.Now().Add(offset))
			s, err := Session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !s.CredentialsStored || !s.RefreshAvailable || s.AccessTokenExpired != (offset < 0) || s.LoginRequired || s.RemotelyVerified || s.RefreshExpiryKnown {
				t.Fatalf("wrong metadata %+v", s)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "fixture") {
				t.Fatal("credentials disclosed")
			}
		})
	}
	sessionFixture(t, time.Time{})
	s, err := Session(context.Background())
	if err != nil || !s.LoginRequired || s.CredentialsStored {
		t.Fatalf("missing session: %v %v", s, err)
	}
	t.Setenv("REPBRIDGE_VAULT_KEY_FILE", "/missing")
	if _, err := Session(context.Background()); err == nil {
		t.Fatal("missing key accepted")
	}
}
func TestRefreshPersistsRotatedCredentialsAndSanitizesErrors(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			store := sessionFixture(t, time.Now().Add(-time.Hour))
			old := http.DefaultTransport
			claims, _ := json.Marshal(map[string]int64{"exp": time.Now().Add(time.Hour).Unix()})
			token := "rotated." + base64.RawURLEncoding.EncodeToString(claims) + ".unsigned"
			calls := 0
			http.DefaultTransport = authRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.String() != garmin.DefaultTokenURL {
					t.Errorf("unexpected renewal endpoint %s", r.URL.Path)
				}
				body := `{"error":"private-upstream-response"}`
				if status == 200 {
					b, _ := json.Marshal(map[string]any{"access_token": token, "refresh_token": "rotated-refresh"})
					body = string(b)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = old })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			s, err := RefreshSession(ctx)
			if status == 200 {
				if err != nil || s.AccessTokenExpired {
					t.Fatalf("renewal failed %v", err)
				}
				c, err := store.Load(ctx)
				if err != nil || c.RefreshToken != "rotated-refresh" {
					t.Fatal("rotation not persisted")
				}
			} else if err == nil || strings.Contains(err.Error(), "private-upstream-response") {
				t.Fatalf("unsafe refresh error %v", err)
			}
			if calls == 0 {
				t.Fatal("no renewal call")
			}
		})
	}
	sessionFixture(t, time.Time{})
	if _, err := RefreshSession(context.Background()); err == nil || !strings.Contains(err.Error(), "login_required") {
		t.Fatal("missing session not reported")
	}
}
func TestOperationCancellationPreventsQueuedCallback(t *testing.T) {
	sessionFixture(t, time.Time{})
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- WithOperation(context.Background(), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	called := false
	err := WithOperation(ctx, func() error { called = true; return nil })
	close(release)
	if err == nil || called {
		t.Fatal("cancelled queued operation ran")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := WithOperation(context.Background(), func() error { return nil }); err != nil {
		t.Fatal("lock not released")
	}
	var out bytes.Buffer
	ctx2, stop := context.WithCancel(context.Background())
	stop()
	MaintainSession(ctx2, &out)
	if out.Len() != 0 {
		t.Fatal("cancelled maintenance logged")
	}
}
func TestBoundedTransportRejectsOversizeAndClosesBody(t *testing.T) {
	for _, size := range []int{0, 1 << 20, (1 << 20) + 1} {
		closed := false
		body := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", size)), closed: &closed}
		transport := boundedTransport{authRoundTripper(func(*http.Request) (*http.Response, error) { return &http.Response{Body: body}, nil })}
		req, _ := http.NewRequest("GET", "https://example.invalid", nil)
		res, err := transport.RoundTrip(req)
		if !closed {
			t.Fatal("upstream body not closed")
		}
		if size > 1<<20 {
			if err == nil {
				t.Fatal("oversize accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(res.Body)
			if len(data) != size {
				t.Fatal("body changed")
			}
		}
	}
}

type trackedBody struct {
	io.Reader
	closed *bool
}

func (b *trackedBody) Close() error { *b.closed = true; return nil }

func TestMaintenanceUsesExpiryAndBacksOffWithCap(t *testing.T) {
	var delays []time.Duration
	var out bytes.Buffer
	attempts := 0
	soon := time.Now().Add(5 * time.Minute)
	maintainSession(context.Background(), &out, func(_ context.Context, d time.Duration) bool { delays = append(delays, d); return len(delays) <= 10 }, func(context.Context) (*SessionStatus, error) {
		return &SessionStatus{CredentialsStored: true, AccessTokenExpiresAt: &soon}, nil
	}, func(ctx context.Context) (*SessionStatus, error) {
		attempts++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("renewal has no deadline")
		}
		return nil, fmt.Errorf("synthetic_failure")
	})
	if attempts != 10 || delays[0] != time.Minute || delays[1] != 2*time.Minute || delays[len(delays)-1] != time.Hour {
		t.Fatalf("backoff %v attempts=%d", delays, attempts)
	}
	if !strings.Contains(out.String(), "synthetic_failure") {
		t.Fatal("maintenance failure not reported")
	}
	far := time.Now().Add(time.Hour)
	attempts = 0
	round := 0
	maintainSession(context.Background(), io.Discard, func(context.Context, time.Duration) bool { round++; return round < 3 }, func(context.Context) (*SessionStatus, error) {
		return &SessionStatus{CredentialsStored: true, AccessTokenExpiresAt: &far}, nil
	}, func(context.Context) (*SessionStatus, error) { attempts++; return nil, nil })
	if attempts != 0 {
		t.Fatal("healthy session unnecessarily renewed")
	}
}
