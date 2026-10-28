package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

const browserLoginTimeout = 5 * time.Minute

// BrowserLoginConfig configures the loopback callback used by Garmin SSO.
// PublicOrigin is the loopback URL a browser on the host uses to reach the
// callback. Docker runs can bind all container interfaces while publishing
// that port only on the host loopback interface.
type BrowserLoginConfig struct {
	ListenAddress string
	PublicOrigin  string
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect Garmin to repbridge</title>
  <style>body{font:16px system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem}iframe{width:100%;height:32rem;border:0}#status{min-height:1.5rem}</style>
</head>
<body>
  <h1>Connect Garmin</h1>
  <p>Sign in on Garmin's page below. repbridge does not receive your password.</p>
  <p>Use a normal Chrome window with third-party cookies allowed. Safari may not display the verification-code form.</p>
  <p id="status" role="status">Waiting for Garmin sign-in…</p>
  <iframe id="garmin-login" title="Garmin sign-in" src="{{.GarminLoginURL}}" referrerpolicy="no-referrer"></iframe>
  <script nonce="{{.Nonce}}">
    const state = {{.StateJSON}};
    const frame = document.getElementById("garmin-login");
    const status = document.getElementById("status");
    let completed = false;
    window.addEventListener("message", async (event) => {
      if (completed || event.origin !== "https://sso.garmin.com" || event.source !== frame.contentWindow) return;
      let message = event.data;
      if (typeof message === "string") {
        try { message = JSON.parse(message); } catch { return; }
      }
      if (!message || message.status !== "SUCCESS" || typeof message.serviceTicket !== "string" || !message.serviceTicket.startsWith("ST-")) return;
      completed = true;
      status.textContent = "Garmin sign-in received. Completing token exchange in the terminal…";
      try {
        const response = await fetch("/callback", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({state, status: message.status, serviceTicket: message.serviceTicket, serviceUrl: typeof message.serviceUrl === "string" ? message.serviceUrl : ""})
        });
        status.textContent = response.ok
          ? "Garmin sign-in received. Return to the terminal for the final connection result."
          : "Sign-in could not be completed. Return to the terminal for details.";
      } catch {
        status.textContent = "Sign-in could not reach the local CLI. Return to the terminal for details.";
      }
    });
  </script>
</body>
</html>`))

type callbackPayload struct {
	State         string `json:"state"`
	Status        string `json:"status"`
	ServiceTicket string `json:"serviceTicket"`
	ServiceURL    string `json:"serviceUrl"`
}

// LoginWithBrowser prints a one-time link for Garmin's sign-in page, then
// exchanges the short-lived SSO ticket for Garmin DI tokens. It never opens a
// browser or reads a password.
func LoginWithBrowser(ctx context.Context, out io.Writer, config BrowserLoginConfig) (*garmin.Credentials, error) {
	if out == nil {
		return nil, fmt.Errorf("write Garmin sign-in link: output is unavailable")
	}
	state, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("create browser sign-in state")
	}
	listenAddress := config.ListenAddress
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("start local Garmin sign-in callback: %w", err)
	}
	defer listener.Close()

	origin := config.PublicOrigin
	if origin == "" {
		origin = "http://" + listener.Addr().String()
	}
	if err := validateBrowserOrigin(origin, listener.Addr()); err != nil {
		return nil, err
	}
	pageURL, err := buildBrowserLoginURL(origin, state)
	if err != nil {
		return nil, err
	}
	tickets := make(chan callbackPayload, 1)
	server := &http.Server{
		Handler:           browserTicketHandler(state, origin, tickets),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if _, err := fmt.Fprintf(out, "Open this link in a normal Chrome window on this machine to sign in to Garmin Connect. Third-party cookies must be allowed:\n%s\n", pageURL); err != nil {
		return nil, fmt.Errorf("write Garmin sign-in link: %w", err)
	}

	loginCtx, cancel := context.WithTimeout(ctx, browserLoginTimeout)
	defer cancel()
	var ticket callbackPayload
	select {
	case ticket = <-tickets:
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			return nil, fmt.Errorf("local Garmin sign-in callback stopped: %w", err)
		}
		return nil, fmt.Errorf("local Garmin sign-in callback stopped")
	case <-loginCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("Garmin browser sign-in timed out after %s", browserLoginTimeout)
	}
	// Garmin may bind the ticket to the widget's source rather than its
	// configured Garmin service. Accept only this session's exact validated
	// loopback origin in addition to the public service allowlist. The URL is
	// a form value sent to DI, never a destination for an HTTP request.
	if ticket.ServiceURL != origin && !validTicketServiceURL(ticket.ServiceURL) {
		return nil, fmt.Errorf("Garmin browser sign-in returned an unsupported ticket service URL (%s)", unsupportedTicketServiceReason(ticket.ServiceURL))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	credentials, err := exchangeServiceTicket(loginCtx, client, diTokenURL, ticket.ServiceTicket, ticket.ServiceURL, diClientIDs)
	if err != nil {
		// ServiceURL exactly matches a public Garmin service or our local origin.
		return nil, fmt.Errorf("browser sign-in service %s: %w", ticket.ServiceURL, err)
	}
	return credentials, nil
}

func validTicketServiceURL(serviceURL string) bool {
	switch serviceURL {
	case garminSSOServiceURL, "https://connect.garmin.com/app", "https://connect.garmin.com/modern", "https://mobile.integration.garmin.com/gcm/ios", "https://mobile.integration.garmin.com/gcm/android":
		return true
	default:
		return false
	}
}

// Report a bounded category without exposing an untrusted service URL.
func unsupportedTicketServiceReason(serviceURL string) string {
	if serviceURL == "" {
		return "missing serviceUrl"
	}
	decoded := serviceURL
	for range 2 {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		if validTicketServiceURL(next) {
			return "encoded serviceUrl"
		}
		decoded = next
	}
	return "unrecognized service"
}

func buildBrowserLoginURL(origin, state string) (string, error) {
	if _, err := buildGarminLoginURL(origin); err != nil {
		return "", err
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("invalid loopback Garmin sign-in origin")
	}
	u.Path = "/"
	query := u.Query()
	query.Set("state", state)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func validateBrowserOrigin(origin string, listenerAddr net.Addr) error {
	if _, err := buildGarminLoginURL(origin); err != nil {
		return err
	}
	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid loopback Garmin sign-in origin")
	}
	_, listenerPort, err := net.SplitHostPort(listenerAddr.String())
	if err != nil || parsedOrigin.Port() != listenerPort {
		return fmt.Errorf("Garmin sign-in origin port must match the local callback port")
	}
	return nil
}

func browserTicketHandler(state, localOrigin string, tickets chan<- callbackPayload) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "invalid sign-in state", http.StatusForbidden)
			return
		}
		loginURL, err := buildGarminLoginURL(localOrigin)
		if err != nil {
			http.Error(w, "could not prepare Garmin sign-in", http.StatusInternalServerError)
			return
		}
		nonce, err := randomToken(18)
		if err != nil {
			http.Error(w, "could not prepare Garmin sign-in", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-src https://sso.garmin.com; connect-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(w, struct {
			GarminLoginURL template.URL
			Nonce          string
			StateJSON      template.JS
		}{
			GarminLoginURL: template.URL(loginURL),
			Nonce:          nonce,
			StateJSON:      template.JS(mustJSONString(state)),
		})
	})
	mux.HandleFunc("POST /callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != localOrigin {
			http.Error(w, "invalid callback origin", http.StatusForbidden)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid callback content type", http.StatusUnsupportedMediaType)
			return
		}
		body := http.MaxBytesReader(w, r.Body, 4096)
		defer body.Close()
		var payload callbackPayload
		dec := json.NewDecoder(body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil {
			http.Error(w, "invalid callback payload", http.StatusBadRequest)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid callback payload", http.StatusBadRequest)
			return
		}
		if payload.State != state || payload.Status != "SUCCESS" || !validServiceTicket(payload.ServiceTicket) {
			http.Error(w, "invalid callback state, success event, or ticket", http.StatusForbidden)
			return
		}
		select {
		case tickets <- payload:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "sign-in already completed", http.StatusConflict)
		}
	})
	return mux
}

func buildGarminLoginURL(localOrigin string) (string, error) {
	parsedOrigin, err := url.Parse(localOrigin)
	if err != nil || parsedOrigin == nil {
		return "", fmt.Errorf("invalid loopback Garmin sign-in origin")
	}
	ip := net.ParseIP(parsedOrigin.Hostname())
	if parsedOrigin.Scheme != "http" || parsedOrigin.Host == "" || parsedOrigin.User != nil ||
		ip == nil || !ip.IsLoopback() || parsedOrigin.Port() == "" || parsedOrigin.Path != "" || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" {
		return "", fmt.Errorf("invalid loopback Garmin sign-in origin")
	}
	u, _ := url.Parse("https://sso.garmin.com/sso/signin")
	q := u.Query()
	q.Set("id", "gauth-widget")
	q.Set("embedWidget", "true")
	q.Set("gauthHost", "https://sso.garmin.com/sso")
	q.Set("service", garminSSOServiceURL)
	q.Set("source", localOrigin)
	q.Set("consumeServiceTicket", "false")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func validServiceTicket(ticket string) bool {
	if !strings.HasPrefix(ticket, "ST-") || len(ticket) > 2048 {
		return false
	}
	for _, r := range ticket {
		if r <= 0x20 || r == '"' || r == '<' || r == '>' || r == '\\' {
			return false
		}
	}
	return true
}

func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func mustJSONString(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}
