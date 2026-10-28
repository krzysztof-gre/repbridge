package access

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializePreservesPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.key")
	var out bytes.Buffer
	if err := Initialize(path, &out); err != nil {
		t.Fatal(err)
	}
	key, err := ReadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || strings.Contains(out.String(), hex.EncodeToString(key)) {
		t.Fatal("invalid or disclosed key")
	}
	before, _ := os.ReadFile(path)
	if err := Initialize(path, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key replaced")
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(path, &out); err == nil {
		t.Fatal("invalid existing key accepted")
	}
	if err := Initialize(filepath.Join(path, "missing"), &out); err == nil {
		t.Fatal("invalid directory accepted")
	}
}
func TestBearerRejectsAmbiguousAndBrowserRequests(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	auth := "Bearer " + hex.EncodeToString(key)
	for _, tc := range []struct {
		name   string
		auth   []string
		origin string
		code   int
	}{
		{"valid", []string{auth}, "", 204}, {"missing", nil, "", 401}, {"wrong", []string{"Bearer wrong"}, "", 401},
		{"duplicate", []string{auth, auth}, "", 401}, {"browser", []string{auth}, "https://attacker.example", 403},
		{"null_origin", []string{auth}, "null", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := Bearer(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) }))
			req := httptest.NewRequest("POST", "http://localhost/mcp", nil)
			for _, v := range tc.auth {
				req.Header.Add("Authorization", v)
			}
			req.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.code || called != (tc.code == 204) {
				t.Fatalf("status=%d called=%v", w.Code, called)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing security headers")
			}
			if strings.Contains(w.Body.String(), hex.EncodeToString(key)) {
				t.Fatal("key leaked")
			}
		})
	}
}
func TestReadKeyRejectsMalformedFiles(t *testing.T) {
	for _, data := range []string{"", "bad", strings.Repeat("g", 64), strings.Repeat("a", 62), strings.Repeat("a", 129)} {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadKey(path); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
