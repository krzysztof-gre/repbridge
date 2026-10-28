package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

// SessionStatus contains metadata only. Stored tokens are not proof of remote
// validity; Garmin does not provide a guaranteed refresh-token expiry here.
type SessionStatus struct {
	CredentialsStored    bool       `json:"credentialsStored"`
	AccessTokenExpiresAt *time.Time `json:"accessTokenExpiresAt"`
	AccessTokenExpired   bool       `json:"accessTokenExpired"`
	RefreshAvailable     bool       `json:"refreshAvailable"`
	RefreshExpiryKnown   bool       `json:"refreshExpiryKnown"`
	AutomaticRefresh     bool       `json:"automaticRefresh"`
	LoginRequired        bool       `json:"loginRequired"`
	RemotelyVerified     bool       `json:"remotelyVerified"`
}

func sessionStatus(creds *garmin.Credentials) *SessionStatus {
	status := &SessionStatus{CredentialsStored: true, RefreshAvailable: creds.RefreshToken != "", AutomaticRefresh: true}
	if expiry := creds.Expiry().UTC(); !expiry.IsZero() {
		status.AccessTokenExpiresAt = &expiry
		status.AccessTokenExpired = !time.Now().Before(expiry)
	}
	return status
}

func Session(ctx context.Context) (*SessionStatus, error) {
	store, err := ConfiguredTokenStore()
	if err != nil {
		return nil, fmt.Errorf("vault_unavailable: Garmin vault is unavailable")
	}
	creds, err := store.Load(ctx)
	if errors.Is(err, garmin.ErrNoCredentials) {
		return &SessionStatus{LoginRequired: true, AutomaticRefresh: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vault_unavailable: Garmin vault cannot be read")
	}
	return sessionStatus(creds), nil
}

// RefreshSession delegates locking, reload, refresh and persistence to the
// upstream RefreshStore implementation. It never implements the grant itself.
func RefreshSession(ctx context.Context) (*SessionStatus, error) {
	var status *SessionStatus
	err := WithOperation(ctx, func() error {
		var err error
		status, err = refreshSession(ctx)
		return err
	})
	return status, err
}

func refreshSession(ctx context.Context) (*SessionStatus, error) {
	store, err := ConfiguredTokenStore()
	if err != nil {
		return nil, fmt.Errorf("vault_unavailable: Garmin vault is unavailable")
	}
	creds, err := garmin.RefreshStore(ctx, store)
	if err != nil {
		if errors.Is(err, garmin.ErrNoCredentials) {
			return nil, fmt.Errorf("garmin_login_required: run the Docker auth login command")
		}
		if errors.Is(err, garmin.ErrRateLimited) {
			return nil, fmt.Errorf("garmin_rate_limited: wait before requesting refresh again")
		}
		var apiError *garmin.APIError
		if errors.As(err, &apiError) && (apiError.StatusCode == 400 || apiError.StatusCode == 401 || apiError.StatusCode == 403) {
			return nil, fmt.Errorf("garmin_login_required: Garmin rejected renewal; run the Docker auth login command")
		}
		// Upstream errors may include response bodies. Return a fixed message.
		return nil, fmt.Errorf("refresh_failed: renewal or encrypted persistence failed; inspect local storage and sign in again if renewal is rejected")
	}
	return sessionStatus(creds), nil
}

// MaintainSession supplies only scheduling. Refresh protocol and rotation
// remain upstream responsibilities. Failed attempts back off up to one hour.
func MaintainSession(ctx context.Context, out io.Writer) {
	maintainSession(ctx, out, waitForMaintenance, Session, RefreshSession)
}

func waitForMaintenance(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Scheduling is independent of the upstream refresh transaction. Tests supply
// a virtual clock; production always uses the real timer and store operations.
func maintainSession(ctx context.Context, out io.Writer,
	wait func(context.Context, time.Duration) bool,
	inspect func(context.Context) (*SessionStatus, error),
	renew func(context.Context) (*SessionStatus, error)) {
	delay := time.Minute
	for wait(ctx, delay) {
		attempt, cancel := context.WithTimeout(ctx, 40*time.Second)
		status, err := inspect(attempt)
		if err == nil && status.CredentialsStored && status.AccessTokenExpiresAt != nil && time.Until(*status.AccessTokenExpiresAt) < 15*time.Minute {
			_, err = renew(attempt)
		}
		cancel()
		if err == nil {
			delay = time.Minute
			continue
		}
		_, _ = fmt.Fprintf(out, "Garmin session maintenance: %s\n", err)
		delay *= 2
		if delay > time.Hour {
			delay = time.Hour
		}
	}
}
