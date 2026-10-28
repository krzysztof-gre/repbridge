// Package access protects private HTTP endpoints with a separately mounted key.
package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/krzysztof-gre/repbridge/internal/secretfile"
)

// Initialize creates an access key in the explicitly mounted config directory.
// It preserves an existing key and prints its path, never its contents.
func Initialize(path string, out io.Writer) error {
	if _, err := os.Lstat(path); err == nil {
		if _, err := ReadKey(path); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Kept existing private HTTP access key")
		return err
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect HTTP access key")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate HTTP access key")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mcp-key-*")
	if err != nil {
		return fmt.Errorf("create HTTP access key in the mounted config directory")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0o640); err != nil {
		return err
	}
	if _, err := io.WriteString(f, hex.EncodeToString(key)+"\n"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("publish HTTP access key without overwriting an existing file")
	}
	_, err = fmt.Fprintln(out, "Created private HTTP access key; contents were not displayed")
	return err
}

// ReadKey reads a 32-byte random key encoded as 64 hexadecimal characters.
// This is an application access key, never a Garmin credential or vault key.
func ReadKey(path string) ([]byte, error) {
	data, err := secretfile.Read(path, 128)
	if err != nil {
		return nil, fmt.Errorf("access key must be a private regular file; run the Docker init-access command")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("access key file must contain a random 32-byte hexadecimal key")
	}
	return key, nil
}

func Bearer(key []byte, next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + hex.EncodeToString(key)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Browsers are not API clients. Reject cross-origin requests and require
		// explicit bearer authorization on every HTTP request, including MCP.
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser origins are not allowed", http.StatusForbidden)
			return
		}
		provided := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 || len(r.Header.Values("Authorization")) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="repbridge"`)
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
