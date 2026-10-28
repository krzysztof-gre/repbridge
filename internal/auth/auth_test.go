package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

type authRoundTripper func(*http.Request) (*http.Response, error)

func (f authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type loginLinkWriter struct{ links chan string }

func (w loginLinkWriter) Write(data []byte) (int, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "http://127.0.0.1:") {
			w.links <- line
		}
	}
	return len(data), nil
}

func TestBrowserLoginExchangesTicketForTheServiceReportedByGarmin(t *testing.T) {
	credentials, err := runBrowserLoginWithReportedService(t, "https://connect.garmin.com/app")
	if err != nil {
		t.Fatal(err)
	}
	if credentials == nil || credentials.AccessToken != "fixture-access" {
		t.Fatal("login did not return the exchanged credentials")
	}
}

func TestBrowserLoginExchangesTicketBoundToItsOwnLoopbackOrigin(t *testing.T) {
	credentials, err := runBrowserLoginWithService(t, func(origin string) string { return origin })
	if err != nil {
		t.Fatal(err)
	}
	if credentials == nil || credentials.AccessToken != "fixture-access" {
		t.Fatal("login did not exchange the ticket bound to its own origin")
	}
}

func TestBrowserLoginRejectsAnotherLoopbackOrigin(t *testing.T) {
	credentials, err := runBrowserLoginWithService(t, func(origin string) string { return origin + "/" })
	if credentials != nil || err == nil || !strings.Contains(err.Error(), "unsupported ticket service") {
		t.Fatalf("login accepted a service different from its own exact origin: %v", err)
	}
}

func TestBrowserLoginRejectsUnsupportedTicketServicesWithoutLeakingThem(t *testing.T) {
	for _, tc := range []struct{ name, serviceURL, reason string }{
		{"external service", "https://attacker.example/?ticket=ST-private", "unrecognized service"},
		{"missing service", "", "missing serviceUrl"},
		{"encoded service", "https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed", "encoded serviceUrl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentials, err := runBrowserLoginWithReportedService(t, tc.serviceURL)
			if credentials != nil || err == nil || !strings.Contains(err.Error(), "unsupported ticket service") || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("login did not reject the ticket service with safe category %q: %v", tc.reason, err)
			}
			if strings.Contains(err.Error(), "attacker.example") || strings.Contains(err.Error(), "ST-private") {
				t.Fatal("login error exposed an untrusted service URL")
			}
		})
	}
}

func runBrowserLoginWithReportedService(t *testing.T, reportedService string) (*garmin.Credentials, error) {
	t.Helper()
	return runBrowserLoginWithService(t, func(string) string { return reportedService })
}

func runBrowserLoginWithService(t *testing.T, serviceForOrigin func(string) string) (*garmin.Credentials, error) {
	t.Helper()
	var reportedService string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("service_url") != reportedService {
			http.Error(w, `{"error":"invalid_request","error_description":"invalid service ticket provided"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture-access", "refresh_token": "fixture-refresh"})
	}))
	defer tokenServer.Close()
	tokenURL, err := url.Parse(tokenServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport
	http.DefaultTransport = authRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == diTokenURL {
			r = r.Clone(r.Context())
			requestURL := *r.URL
			requestURL.Scheme, requestURL.Host = tokenURL.Scheme, tokenURL.Host
			r.URL = &requestURL
		}
		return transport.RoundTrip(r)
	})
	defer func() { http.DefaultTransport = transport }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	links := make(chan string, 1)
	finished := make(chan struct{})
	var credentials *garmin.Credentials
	var loginErr error
	go func() {
		defer close(finished)
		credentials, loginErr = LoginWithBrowser(ctx, loginLinkWriter{links}, BrowserLoginConfig{ListenAddress: "127.0.0.1:0"})
	}()
	defer func() { cancel(); <-finished }()
	var link string
	select {
	case link = <-links:
	case <-finished:
		t.Fatalf("login stopped before printing a link: %v", loginErr)
	case <-ctx.Done():
		t.Fatal("login did not print a link")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	origin := u.Scheme + "://" + u.Host
	reportedService = serviceForOrigin(origin)
	callback, err := json.Marshal(map[string]string{
		"state": u.Query().Get("state"), "status": "SUCCESS", "serviceTicket": "ST-fixture", "serviceUrl": reportedService,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := json.Marshal(map[string]string{"state": u.Query().Get("state"), "serviceTicket": "ST-intermediate"})
	if err != nil {
		t.Fatal(err)
	}
	intermediateReq, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/callback", strings.NewReader(string(intermediate)))
	if err != nil {
		t.Fatal(err)
	}
	intermediateReq.Header.Set("Origin", origin)
	intermediateReq.Header.Set("Content-Type", "application/json")
	intermediateResponse, err := (&http.Client{Transport: transport}).Do(intermediateReq)
	if err != nil {
		t.Fatal(err)
	}
	intermediateResponse.Body.Close()
	if intermediateResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("intermediate callback status = %d, want 403 and continued wait for SUCCESS", intermediateResponse.StatusCode)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/callback", strings.NewReader(string(callback)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("callback status = %d, want 204", response.StatusCode)
	}
	<-finished
	return credentials, loginErr
}

func TestExchangeServiceTicketFallsBackAndReturnsTokens(t *testing.T) {
	var gotClientIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.Form.Get("service_ticket"); got != "ST-one-time-ticket" {
			t.Errorf("service_ticket = %q", got)
		}
		if got := r.Form.Get("service_url"); got != garminSSOServiceURL {
			t.Errorf("service_url = %q", got)
		}
		if got := r.Form.Get("grant_type"); got != diGrantType {
			t.Errorf("grant_type = %q", got)
		}
		gotClientIDs = append(gotClientIDs, r.Form.Get("client_id"))
		if len(gotClientIDs) == 1 {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "header.eyJleHAiOjIwMDAwMDAwMDAsImNsaWVudF9pZCI6IkdBUk1JTl9DT05ORUNUX01PQklMRV9BTkRST0lEX0RJXzIwMjRRNCJ9.signature", // gitleaks:allow synthetic unsigned test JWT
			"refresh_token": "rotating-refresh-token",
		})
	}))
	defer server.Close()

	creds, err := exchangeServiceTicket(context.Background(), server.Client(), server.URL, "ST-one-time-ticket", garminSSOServiceURL, []string{"first-client", "second-client"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotClientIDs) != 2 || gotClientIDs[0] != "first-client" || gotClientIDs[1] != "second-client" {
		t.Fatalf("client ID attempts = %v", gotClientIDs)
	}
	if creds.AccessToken == "" || creds.RefreshToken != "rotating-refresh-token" {
		t.Fatalf("credentials = %+v", creds)
	}
	if creds.ClientID != "GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4" {
		t.Fatalf("client ID = %q, want ID from access token", creds.ClientID)
	}
}

func TestExchangeServiceTicketDoesNotIncludeTicketInErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"ST-do-not-log","error_description":"private response","access_token":"private-token"}`))
	}))
	defer server.Close()

	_, err := exchangeServiceTicket(context.Background(), server.Client(), server.URL, "ST-do-not-log", garminSSOServiceURL, []string{"only-client"})
	if err == nil {
		t.Fatal("exchange succeeded; want error")
	}
	if strings.Contains(err.Error(), "ST-do-not-log") || strings.Contains(err.Error(), "private response") || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("error leaks ticket or response body: %v", err)
	}
}

func TestExchangeServiceTicketReportsSafeOAuthFailuresForEachAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_id") == "first-client" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"ST-private-ticket"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"private details"}`))
	}))
	defer server.Close()

	_, err := exchangeServiceTicket(context.Background(), server.Client(), server.URL, "ST-private-ticket", garminSSOServiceURL, []string{"first-client", "second-client"})
	if err == nil {
		t.Fatal("exchange succeeded; want error")
	}
	for _, want := range []string{"first-client: HTTP 409 invalid_client", "second-client: HTTP 400 invalid_grant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "ST-private-ticket") || strings.Contains(err.Error(), "private details") {
		t.Fatalf("error leaks authentication details: %v", err)
	}
}

func TestExchangeServiceTicketIdentifiesTicketRejectionWithoutResponseDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"invalid service ticket provided","service_ticket":"ST-private","refresh_token":"private-token"}`))
	}))
	defer server.Close()
	_, err := exchangeServiceTicket(context.Background(), server.Client(), server.URL, "ST-private", garminSSOServiceURL, []string{"fixture-client"})
	if err == nil || !strings.Contains(err.Error(), "invalid_request (service ticket rejected)") {
		t.Fatalf("error = %v, want safe ticket rejection diagnostic", err)
	}
	if strings.Contains(err.Error(), "ST-private") || strings.Contains(err.Error(), "private-token") {
		t.Fatal("ticket rejection error leaked authentication details")
	}
}

func TestBrowserTicketHandlerRequiresStateOriginAndGarminMessage(t *testing.T) {
	tickets := make(chan callbackPayload, 1)
	handler := browserTicketHandler("state-123", "http://127.0.0.1:43210", tickets)

	badOrigin := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(`{"state":"state-123","serviceTicket":"ST-test"}`))
	badOrigin.Header.Set("Origin", "https://attacker.example")
	badOrigin.Header.Set("Content-Type", "application/json")
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, badOrigin)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d", badResponse.Code)
	}

	badState := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(`{"state":"wrong","serviceTicket":"ST-test"}`))
	badState.Header.Set("Origin", "http://127.0.0.1:43210")
	badState.Header.Set("Content-Type", "application/json")
	badStateResponse := httptest.NewRecorder()
	handler.ServeHTTP(badStateResponse, badState)
	if badStateResponse.Code != http.StatusForbidden {
		t.Fatalf("bad state status = %d", badStateResponse.Code)
	}

	valid := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(`{"state":"state-123","status":"SUCCESS","serviceTicket":"ST-test","serviceUrl":"https://sso.garmin.com/sso/embed"}`))
	valid.Header.Set("Origin", "http://127.0.0.1:43210")
	valid.Header.Set("Content-Type", "application/json")
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid callback status = %d, body=%s", validResponse.Code, validResponse.Body.String())
	}
	if got := <-tickets; got.ServiceTicket != "ST-test" || got.ServiceURL != garminSSOServiceURL {
		t.Fatalf("ticket = %q", got)
	}
}

func TestBuildGarminLoginURLUsesLoopbackAsBrowserOrigin(t *testing.T) {
	loginURL, err := buildGarminLoginURL("http://127.0.0.1:43210")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "sso.garmin.com" || u.Path != "/sso/signin" {
		t.Fatalf("URL = %s, want Garmin SSO sign-in", loginURL)
	}
	if q.Get("source") != "http://127.0.0.1:43210" || q.Get("service") != garminSSOServiceURL || q.Get("consumeServiceTicket") != "false" {
		t.Fatalf("query = %v", q)
	}
}

func TestBuildGarminLoginURLRejectsMalformedOrigin(t *testing.T) {
	if _, err := buildGarminLoginURL("http://%"); err == nil {
		t.Fatal("buildGarminLoginURL accepted a malformed origin")
	}
}

func TestBuildBrowserLoginURLIncludesLoopbackAddressAndState(t *testing.T) {
	pageURL, err := buildBrowserLoginURL("http://127.0.0.1:8787", "state-123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "127.0.0.1:8787" || u.Path != "/" || u.Query().Get("state") != "state-123" {
		t.Fatalf("browser login URL = %s", pageURL)
	}
}

func TestValidateBrowserOriginMatchesPublishedListener(t *testing.T) {
	listenerAddr := &net.TCPAddr{IP: net.IPv4zero, Port: 8787}
	if err := validateBrowserOrigin("http://127.0.0.1:8787", listenerAddr); err != nil {
		t.Fatalf("valid published browser origin rejected: %v", err)
	}
	for _, origin := range []string{"http://127.0.0.1:8788", "http://192.168.1.5:8787", "http://localhost:8787"} {
		if err := validateBrowserOrigin(origin, listenerAddr); err == nil {
			t.Errorf("invalid browser origin accepted: %s", origin)
		}
	}
}

func TestBrowserTicketHandlerDoesNotServeAUsernameOrPasswordForm(t *testing.T) {
	tickets := make(chan callbackPayload, 1)
	handler := browserTicketHandler("state-123", "http://127.0.0.1:43210", tickets)
	request := httptest.NewRequest(http.MethodGet, "/?state=state-123", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `src="https://sso.garmin.com/sso/signin?`) {
		t.Fatal("page does not embed Garmin's sign-in page")
	}
	if strings.Contains(response.Body.String(), `type="password"`) || strings.Contains(response.Body.String(), `name="password"`) {
		t.Fatal("local page contains a password field")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers = %v", response.Header())
	}
}
