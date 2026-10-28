package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/krzysztof-gre/repbridge/internal/auth"
)

func TestAuthLoginWritesSignInLinkToTerminalOutput(t *testing.T) {
	deps := Dependencies{
		Login: func(_ context.Context, out io.Writer) error {
			_, err := io.WriteString(out, "Open this link: http://127.0.0.1:8787/?state=one-time\n")
			return err
		},
	}
	var output strings.Builder
	if err := RunWithDependencies(context.Background(), []string{"auth", "login"}, strings.NewReader(""), &output, &strings.Builder{}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "http://127.0.0.1:8787/?state=one-time") || !strings.Contains(output.String(), "Connected to Garmin Connect") || !strings.Contains(output.String(), "encrypted local vault") {
		t.Fatalf("auth login output = %q", output.String())
	}
}

func TestConfiguredTokenStoreAlwaysUsesEncryptedVault(t *testing.T) {
	t.Setenv("REPBRIDGE_TOKEN_FILE", t.TempDir()+"/private/credentials.enc")
	keyFilePath := t.TempDir() + "/vault.key"
	if err := os.WriteFile(keyFilePath, make([]byte, 32), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPBRIDGE_VAULT_KEY_FILE", keyFilePath)
	store, err := auth.ConfiguredTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*auth.EncryptedTokenStore); !ok {
		t.Fatalf("configured store has type %T, want encrypted file store", store)
	}
}

func TestBrowserLoginConfigUsesLoopbackDefaultsAndSupportsDocker(t *testing.T) {
	t.Setenv("REPBRIDGE_AUTH_LISTEN_ADDRESS", "")
	t.Setenv("REPBRIDGE_AUTH_PUBLIC_ORIGIN", "")
	if got := browserLoginConfigFromEnv(); got.ListenAddress != "127.0.0.1:0" || got.PublicOrigin != "" {
		t.Fatalf("default browser login config = %+v", got)
	}

	t.Setenv("REPBRIDGE_AUTH_LISTEN_ADDRESS", "0.0.0.0:8787")
	t.Setenv("REPBRIDGE_AUTH_PUBLIC_ORIGIN", "http://127.0.0.1:8787")
	if got := browserLoginConfigFromEnv(); got.ListenAddress != "0.0.0.0:8787" || got.PublicOrigin != "http://127.0.0.1:8787" {
		t.Fatalf("Docker browser login config = %+v", got)
	}
}

func TestAllAuthCommandsDispatchAndPropagateFailure(t *testing.T) {
	for _, command := range []string{"login", "status", "refresh", "logout"} {
		t.Run(command, func(t *testing.T) {
			calls := 0
			fn := func(context.Context, io.Writer) error { calls++; return nil }
			deps := Dependencies{Login: fn, AuthStatus: fn, AuthRefresh: fn, AuthLogout: func(context.Context) error { calls++; return nil }}
			if err := RunWithDependencies(context.Background(), []string{"auth", command}, strings.NewReader(""), io.Discard, io.Discard, deps); err != nil || calls != 1 {
				t.Fatalf("dispatch %v calls=%d", err, calls)
			}
			if err := RunWithDependencies(context.Background(), []string{"auth", command}, nil, io.Discard, io.Discard, Dependencies{}); err == nil {
				t.Fatal("missing dependency accepted")
			}
		})
	}
	for _, args := range [][]string{nil, {"bad"}, {"auth", "bad"}, {"auth", "login", "extra"}} {
		if err := RunWithDependencies(context.Background(), args, nil, io.Discard, io.Discard, Dependencies{}); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"version"}, {"--version"}, {"policy", "actions"}, {"policy", "check", "../../policies/starter.json"}, {"catalog", "check"}} {
		var out strings.Builder
		if err := Run(context.Background(), args, nil, &out, io.Discard); err != nil || out.Len() == 0 {
			t.Fatalf("offline command %v: %v", args, err)
		}
	}
}
