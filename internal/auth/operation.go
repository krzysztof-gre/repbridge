package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

// WithOperation coordinates active calls, login replacement, refresh and logout
// across processes. This lock is distinct from upstream's token-rotation lock.
func WithOperation(ctx context.Context, fn func() error) error {
	path := os.Getenv("REPBRIDGE_TOKEN_FILE")
	if path == "" {
		path = "/data/credentials.enc"
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("Garmin operation storage is unavailable")
	}
	lock := flock.New(path+".operation.lock", flock.SetPermissions(0o600))
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil || !locked {
		return fmt.Errorf("Garmin operation cancelled or busy")
	}
	defer lock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

// WithClient reloads current credentials only after obtaining the operation
// lock. No client with cached credentials survives the invocation.
func WithClient(ctx context.Context, fn func(*garmin.Client) error) error {
	return WithOperation(ctx, func() error {
		store, err := ConfiguredTokenStore()
		if err != nil {
			return fmt.Errorf("Garmin vault is unavailable")
		}
		client, err := garmin.NewClientFromStore(ctx, store, garmin.WithRetry(1, time.Second), garmin.WithHTTPClient(&http.Client{Timeout: 30 * time.Second, Transport: boundedTransport{http.DefaultTransport}}))
		if err != nil {
			return fmt.Errorf("Garmin is not connected or the encrypted vault cannot be read")
		}
		return fn(client)
	})
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	response.Body.Close()
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("Garmin response is unavailable or too large")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}
