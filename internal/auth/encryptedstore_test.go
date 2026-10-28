package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ndeloof/go-garmin/pkg/garmin"
)

func TestEncryptedTokenStoreCreatesEncryptedVaultAndRoundTripsCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credentials.enc")
	key := testVaultKey()
	store := newEncryptedTokenStore(path, key)
	if err := store.UnlockForLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("UnlockForLogin did not create encrypted vault: %v", err)
	}

	want := &garmin.Credentials{AccessToken: "access-secret", RefreshToken: "refresh-secret", ClientID: "client-secret"}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{want.AccessToken, want.RefreshToken, want.ClientID} {
		if strings.Contains(string(contents), secret) {
			t.Fatalf("encrypted vault contains plaintext secret %q", secret)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("vault permissions = %04o, want 0600", info.Mode().Perm())
	}
	if dirInfo, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("vault directory permissions = %04o, want 0700", dirInfo.Mode().Perm())
	}

	reopened := newEncryptedTokenStore(path, key)
	got, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Fatalf("credentials = %+v, want %+v", got, want)
	}
}

func TestEncryptedTokenStoreRejectsWrongKeyAndTampering(t *testing.T) {
	path := testVaultPath(t)
	key := testVaultKey()
	store := newEncryptedTokenStore(path, key)
	if err := store.UnlockForLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), &garmin.Credentials{AccessToken: "access", RefreshToken: "refresh", ClientID: "client"}); err != nil {
		t.Fatal(err)
	}

	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 0xff
	wrong := newEncryptedTokenStore(path, wrongKey)
	if _, err := wrong.Load(context.Background()); err == nil {
		t.Fatal("Load with a wrong key succeeded")
	} else if strings.Contains(err.Error(), "access") || strings.Contains(err.Error(), "refresh") {
		t.Fatalf("wrong-key error leaked credentials: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedTokenEnvelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)/2] ^= 1
	envelope.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	modified, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newEncryptedTokenStore(path, key).Load(context.Background()); err == nil {
		t.Fatal("Load accepted modified ciphertext")
	}
}

func TestEncryptedTokenStoreRejectsUnsupportedEnvelopeVersion(t *testing.T) {
	path := testVaultPath(t)
	store := newEncryptedTokenStore(path, testVaultKey())
	if err := store.UnlockForLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedTokenEnvelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Version++
	modified, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("unsupported envelope version error = %v, want format error", err)
	}
}

func TestEncryptedTokenStoreMissingVaultReturnsNoCredentials(t *testing.T) {
	store := newEncryptedTokenStore(testVaultPath(t), testVaultKey())
	if _, err := store.Load(context.Background()); !errors.Is(err, garmin.ErrNoCredentials) {
		t.Fatalf("Load error = %v, want ErrNoCredentials", err)
	}
}

func TestEncryptedTokenStoreRejectsInsecureFileAndDirectoryPermissions(t *testing.T) {
	path := testVaultPath(t)
	store := newEncryptedTokenStore(path, testVaultKey())
	if err := store.UnlockForLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), &garmin.Credentials{AccessToken: "access", RefreshToken: "refresh", ClientID: "client"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("Load with a permissive file returned %v, want permission error", err)
	}

	directory := filepath.Dir(path)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Lock(context.Background()); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("Lock with a permissive directory returned %v, want permission error", err)
	}
}

func TestEncryptedTokenStoreDeleteSerializesAndRemovesVault(t *testing.T) {
	path := testVaultPath(t)
	store := newEncryptedTokenStore(path, testVaultKey())
	if err := store.UnlockForLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), &garmin.Credentials{AccessToken: "access", RefreshToken: "refresh", ClientID: "client"}); err != nil {
		t.Fatal(err)
	}

	unlock, err := store.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- store.Delete(context.Background()) }()
	select {
	case err := <-deleted:
		unlock()
		t.Fatalf("Delete returned while refresh lock was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault still exists after Delete: %v", err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, garmin.ErrNoCredentials) {
		t.Fatalf("Load after Delete error = %v, want ErrNoCredentials", err)
	}
}

func TestReadVaultKeyRequiresPrivateRegular32ByteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.key")
	key := testVaultKey()
	if err := os.WriteFile(path, key, 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := readVaultKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("readVaultKey returned different key bytes")
	}
	wipe(got)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readVaultKey(path); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("readVaultKey with world-readable permissions error = %v", err)
	}
	if err := os.WriteFile(path, key[:31], 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readVaultKey(path); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("readVaultKey with short file error = %v", err)
	}
	if _, err := readVaultKey(filepath.Join(dir, "missing.key")); err == nil || !strings.Contains(err.Error(), "init-vault-key") {
		t.Fatalf("readVaultKey with missing file error = %v", err)
	}
}

func testVaultKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func testVaultPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "private", "credentials.enc")
}
