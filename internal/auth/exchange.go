package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

const (
	garminSSOServiceURL = "https://sso.garmin.com/sso/embed"
	diTokenURL          = garmin.DefaultTokenURL
	diGrantType         = "https://connectapi.garmin.com/di-oauth2-service/oauth/grant/service_ticket"
	garminUserAgent     = "com.garmin.android.apps.connectmobile"
)

var diClientIDs = []string{
	"GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2",
	"GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4",
	"GARMIN_CONNECT_MOBILE_ANDROID_DI",
	"GARMIN_CONNECT_MOBILE_IOS_DI",
}

// exchangeServiceTicket trades the one-time browser SSO ticket for refreshable
// Garmin DI credentials. Error text deliberately excludes request and response
// bodies because both can contain authentication material.
func exchangeServiceTicket(ctx context.Context, client *http.Client, tokenURL, ticket, serviceURL string, clientIDs []string) (*garmin.Credentials, error) {
	if ticket == "" || serviceURL == "" || len(clientIDs) == 0 {
		return nil, fmt.Errorf("Garmin browser authentication is incomplete")
	}
	if client == nil {
		client = &http.Client{}
	}

	var failures []string
	for _, clientID := range clientIDs {
		form := url.Values{
			"client_id":      {clientID},
			"service_ticket": {ticket},
			"grant_type":     {diGrantType},
			"service_url":    {serviceURL},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("create Garmin token exchange request: %w", err)
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", garminUserAgent)
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Garmin token exchange request failed: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read Garmin token exchange response: %w", readErr)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			failure := fmt.Sprintf("%s: HTTP %d", clientID, resp.StatusCode)
			if code := safeOAuthFailure(body); code != "" {
				failure += " " + code
			}
			failures = append(failures, failure)
			if resp.StatusCode == http.StatusTooManyRequests {
				return nil, fmt.Errorf("Garmin authentication is rate limited; wait before trying again")
			}
			continue
		}

		var tokenResponse struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &tokenResponse); err != nil || tokenResponse.AccessToken == "" || tokenResponse.RefreshToken == "" {
			return nil, fmt.Errorf("Garmin returned an invalid token response")
		}
		actualClientID := clientID
		if fromToken := clientIDFromAccessToken(tokenResponse.AccessToken); fromToken != "" {
			actualClientID = fromToken
		}
		return &garmin.Credentials{
			AccessToken:  tokenResponse.AccessToken,
			RefreshToken: tokenResponse.RefreshToken,
			ClientID:     actualClientID,
		}, nil
	}
	if len(failures) != 0 {
		return nil, fmt.Errorf("Garmin token exchange failed (%s)", strings.Join(failures, "; "))
	}
	return nil, fmt.Errorf("Garmin token exchange failed")
}

// Display only standard OAuth identifiers and exact, known error categories.
// Arbitrary descriptions may contain tickets or other authentication material.
func safeOAuthFailure(body []byte) string {
	var response struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return ""
	}
	if response.Error == "invalid_request" && response.Description == "invalid service ticket provided" {
		return "invalid_request (service ticket rejected)"
	}
	switch response.Error {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "server_error", "temporarily_unavailable":
		return response.Error
	default:
		return ""
	}
}

func clientIDFromAccessToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.ClientID
}
