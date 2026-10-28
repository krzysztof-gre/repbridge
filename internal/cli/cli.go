package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/krzysztof-gre/repbridge/internal/access"
	"github.com/krzysztof-gre/repbridge/internal/auth"
	"github.com/krzysztof-gre/repbridge/internal/buildinfo"
	"github.com/krzysztof-gre/repbridge/internal/mcpserver"
	"github.com/krzysztof-gre/repbridge/internal/policy"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

// Dependencies isolates the remaining CLI authentication operations.
type Dependencies struct {
	Login       func(context.Context, io.Writer) error
	AuthStatus  func(context.Context, io.Writer) error
	AuthRefresh func(context.Context, io.Writer) error
	AuthLogout  func(context.Context) error
}

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		_, err := fmt.Fprintln(out, buildinfo.Version)
		return err
	}
	if len(args) == 2 && args[0] == "catalog" && args[1] == "check" {
		return mcpserver.CheckCatalogue(ctx, out)
	}
	if len(args) > 0 && args[0] == "policy" {
		return policy.Run(args[1:], out)
	}
	if len(args) > 0 && args[0] == "mcp" {
		return mcpserver.Run(ctx, args[1:], out, errOut)
	}
	if len(args) == 2 && args[0] == "gateway" && args[1] == "check" {
		return mcpserver.CheckGateway(ctx, out)
	}
	if len(args) == 1 && args[0] == "init-access" {
		return access.Initialize("/config/mcp.key", out)
	}
	return RunWithDependencies(ctx, args, in, out, errOut, Dependencies{Login: loginToGarmin, AuthStatus: reportAuthStatus, AuthRefresh: refreshGarmin, AuthLogout: logoutFromGarmin})
}

func RunWithDependencies(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, deps Dependencies) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprintln(out, `RepBridge (repbridge) — policy-controlled Garmin MCP in Docker

Commands:
  version                     Print the application release version
  auth login                  Print a short-lived browser sign-in link
  auth status                 Print credential-free session metadata
  auth refresh                Manually renew and encrypt the rotated tokens
  auth logout                 Remove the saved credentials
  mcp                         Serve upstream workout tools over stdio
  mcp --transport http        Serve private Streamable HTTP at /mcp
  mcp --transport tunnel      Connect through OpenAI Secure MCP Tunnel
  gateway check               Inspect gateway mounts/policy/vault offline
  init-access                 Initialize the separately mounted HTTP access key
  catalog check               Validate all classified tools/schemas offline
  policy check [file]          Validate the owner access policy without Garmin
  policy actions              List all classified capabilities
  policy explain --action ... Explain a hypothetical decision without Garmin

Workouts use native Garmin JSON through MCP create_workout.
Use get_workout_schema and search_exercises in MCP.`)
		return err
	}
	if len(args) != 2 || args[0] != "auth" {
		return fmt.Errorf("use repbridge help for supported commands")
	}
	switch args[1] {
	case "login":
		if deps.Login == nil {
			return fmt.Errorf("Garmin browser login is unavailable")
		}
		if err := deps.Login(ctx, out); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Connected to Garmin Connect. Tokens are stored in the encrypted local vault.")
		return err
	case "status":
		if deps.AuthStatus == nil {
			return fmt.Errorf("Garmin auth status is unavailable")
		}
		return deps.AuthStatus(ctx, out)
	case "refresh":
		if deps.AuthRefresh == nil {
			return fmt.Errorf("Garmin manual refresh is unavailable")
		}
		return deps.AuthRefresh(ctx, out)
	case "logout":
		if deps.AuthLogout == nil {
			return fmt.Errorf("Garmin logout is unavailable")
		}
		if err := deps.AuthLogout(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Garmin tokens removed from the encrypted local vault.")
		return err
	default:
		return fmt.Errorf("usage: repbridge auth <login|status|refresh|logout>")
	}
}

func loginToGarmin(ctx context.Context, out io.Writer) error {
	store, err := auth.ConfiguredTokenStore()
	if err != nil {
		return err
	}
	if unlockable, ok := store.(interface{ UnlockForLogin(context.Context) error }); ok {
		if err := unlockable.UnlockForLogin(ctx); err != nil {
			return err
		}
	}
	credentials, err := auth.LoginWithBrowser(ctx, out, browserLoginConfigFromEnv())
	if err != nil {
		return err
	}
	client := garmin.NewClient(credentials)
	if _, err := client.UserProfile.SocialProfile(ctx); err != nil {
		return fmt.Errorf("verify Garmin browser sign-in failed")
	}
	return auth.WithOperation(ctx, func() error {
		unlock, err := store.Lock(ctx)
		if err != nil {
			return err
		}
		defer unlock()
		return store.Save(ctx, client.Credentials())
	})
}

func browserLoginConfigFromEnv() auth.BrowserLoginConfig {
	address := os.Getenv("REPBRIDGE_AUTH_LISTEN_ADDRESS")
	if address == "" {
		address = "127.0.0.1:0"
	}
	return auth.BrowserLoginConfig{ListenAddress: address, PublicOrigin: os.Getenv("REPBRIDGE_AUTH_PUBLIC_ORIGIN")}
}

func reportAuthStatus(ctx context.Context, out io.Writer) error {
	status, err := auth.Session(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}

func refreshGarmin(ctx context.Context, out io.Writer) error {
	status, err := auth.RefreshSession(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}

func logoutFromGarmin(ctx context.Context) error {
	store, err := auth.ConfiguredTokenStore()
	if err != nil {
		return err
	}
	return auth.WithOperation(ctx, func() error { return store.Delete(ctx) })
}
