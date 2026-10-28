package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/krzysztof-gre/repbridge/internal/secretfile"
	"github.com/ndeloof/go-garmin/pkg/garmin"
)

const (
	encryptedStoreVersion = 2
	encryptedStoreCipher  = "aes-256-gcm"
	// Immutable v2 format identifier: changing it would invalidate existing vaults.
	encryptedStoreAAD     = "gptworkout2garminconnect encrypted token store v2"
	maxEncryptedStoreSize = 1 << 20
	vaultKeyBytes         = 32
)

// CredentialStore is the subset of credential-store operations used by this
// CLI and the Garmin client.
type CredentialStore interface {
	garmin.LockingTokenStore
	Delete(context.Context) error
}

// EncryptedTokenStore stores Garmin credentials in an authenticated encrypted
// file. Its random AES key is read from a separate, read-only mounted file.
// Save is called while the Garmin client's refresh lock is held.
type EncryptedTokenStore struct {
	path string
	key  []byte

	mu sync.Mutex
}

type encryptedTokenEnvelope struct {
	Version    int    `json:"version"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type encryptedTokenPayload struct {
	Credentials *garmin.Credentials `json:"credentials"`
}

// NewEncryptedTokenStore creates a file-backed credential store using a random
// key read from keyFilePath. The key is never accepted through an environment
// variable or command argument.
func NewEncryptedTokenStore(path, keyFilePath string) (*EncryptedTokenStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("encrypted credential vault path must not be empty")
	}
	key, err := readVaultKey(keyFilePath)
	if err != nil {
		return nil, err
	}
	return &EncryptedTokenStore{path: path, key: key}, nil
}

func newEncryptedTokenStore(path string, key []byte) *EncryptedTokenStore {
	return &EncryptedTokenStore{path: path, key: append([]byte(nil), key...)}
}

// UnlockForLogin validates the key against an existing vault or creates an
// empty encrypted vault before Garmin's browser sign-in begins.
func (s *EncryptedTokenStore) UnlockForLogin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := s.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	envelope, err := s.readEnvelope()
	if err == nil {
		_, decryptErr := decryptTokenPayload(envelope, s.key)
		return decryptErr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.writePayload(s.key, encryptedTokenPayload{})
}

// Load reads and decrypts Garmin tokens. A missing vault is equivalent to an
// unconnected account and never creates a token file.
func (s *EncryptedTokenStore) Load(ctx context.Context) (*garmin.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	envelope, err := s.readEnvelope()
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Garmin is not connected; run `docker compose run --rm --service-ports -it repbridge auth login`: %w", garmin.ErrNoCredentials)
	}
	if err != nil {
		return nil, err
	}
	payload, err := decryptTokenPayload(envelope, s.key)
	if err != nil {
		return nil, err
	}
	if payload.Credentials == nil {
		return nil, fmt.Errorf("Garmin is not connected; run `docker compose run --rm --service-ports -it repbridge auth login`: %w", garmin.ErrNoCredentials)
	}
	if err := validateCredentials(payload.Credentials); err != nil {
		return nil, err
	}
	return payload.Credentials, nil
}

// Save atomically replaces the encrypted credential envelope. The caller must
// hold Lock while participating in a Garmin refresh-token rotation.
func (s *EncryptedTokenStore) Save(ctx context.Context, credentials *garmin.Credentials) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentials(credentials); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != vaultKeyBytes {
		return fmt.Errorf("encrypted credential vault key is unavailable")
	}
	return s.writePayload(s.key, encryptedTokenPayload{Credentials: credentials})
}

// Delete removes the encrypted credential file and waits for any active
// refresh-token rotation to finish.
func (s *EncryptedTokenStore) Delete(ctx context.Context) error {
	unlock, err := s.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.key)
	s.key = nil
	err = os.Remove(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove encrypted credential vault: %w", err)
	}
	return nil
}

// Lock serializes refresh-token rotation across CLI processes sharing a vault.
func (s *EncryptedTokenStore) Lock(ctx context.Context) (func(), error) {
	if err := ensurePrivateDirectory(filepath.Dir(s.path)); err != nil {
		return nil, err
	}
	lock := flock.New(s.path+".lock", flock.SetPermissions(0o600))
	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("lock encrypted Garmin credential vault: %w", err)
	}
	if !locked {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("lock encrypted Garmin credential vault: context ended")
	}
	return func() { _ = lock.Unlock() }, nil
}

func (s *EncryptedTokenStore) readEnvelope() (encryptedTokenEnvelope, error) {
	var envelope encryptedTokenEnvelope
	info, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return envelope, os.ErrNotExist
		}
		return envelope, fmt.Errorf("read encrypted credential vault")
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxEncryptedStoreSize {
		return envelope, fmt.Errorf("encrypted credential vault format is invalid")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return envelope, fmt.Errorf("encrypted credential vault permissions are too open; set the file to 0600")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return envelope, fmt.Errorf("read encrypted credential vault")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return envelope, fmt.Errorf("encrypted credential vault format is invalid")
	}
	if openedInfo.Mode().Perm()&0o077 != 0 {
		return envelope, fmt.Errorf("encrypted credential vault permissions are too open; set the file to 0600")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxEncryptedStoreSize+1))
	if err != nil || len(contents) > maxEncryptedStoreSize {
		return envelope, fmt.Errorf("read encrypted credential vault")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("encrypted credential vault format is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return envelope, fmt.Errorf("encrypted credential vault format is invalid")
	}
	if err := validateEnvelope(envelope); err != nil {
		return envelope, err
	}
	return envelope, nil
}

func (s *EncryptedTokenStore) writePayload(key []byte, payload encryptedTokenPayload) error {
	if len(key) != vaultKeyBytes {
		return fmt.Errorf("encrypted credential vault key is unavailable")
	}
	if err := ensurePrivateDirectory(filepath.Dir(s.path)); err != nil {
		return err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode encrypted credential vault")
	}
	defer wipe(plaintext)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("encrypt credential vault")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("encrypt credential vault")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("encrypt credential vault")
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(encryptedStoreAAD))
	envelope := encryptedTokenEnvelope{
		Version:    encryptedStoreVersion,
		Cipher:     encryptedStoreCipher,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}
	contents, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode encrypted credential vault")
	}
	return atomicWritePrivateFile(s.path, contents)
}

func decryptTokenPayload(envelope encryptedTokenEnvelope, key []byte) (encryptedTokenPayload, error) {
	var payload encryptedTokenPayload
	if err := validateEnvelope(envelope); err != nil {
		return payload, err
	}
	if len(key) != vaultKeyBytes {
		return payload, fmt.Errorf("encrypted credential vault cannot be unlocked")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return payload, fmt.Errorf("encrypted credential vault format is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return payload, fmt.Errorf("encrypted credential vault format is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return payload, fmt.Errorf("encrypted credential vault cannot be unlocked")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return payload, fmt.Errorf("encrypted credential vault cannot be unlocked")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(encryptedStoreAAD))
	if err != nil {
		return payload, fmt.Errorf("encrypted credential vault cannot be unlocked")
	}
	defer wipe(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return encryptedTokenPayload{}, fmt.Errorf("encrypted credential vault contents are invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return encryptedTokenPayload{}, fmt.Errorf("encrypted credential vault contents are invalid")
	}
	return payload, nil
}

func validateEnvelope(envelope encryptedTokenEnvelope) error {
	if envelope.Version != encryptedStoreVersion || envelope.Cipher != encryptedStoreCipher {
		return fmt.Errorf("encrypted credential vault format is invalid")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 {
		return fmt.Errorf("encrypted credential vault format is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxEncryptedStoreSize {
		return fmt.Errorf("encrypted credential vault format is invalid")
	}
	return nil
}

func readVaultKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("encrypted credential vault key file path must not be empty")
	}
	key, err := secretfile.Read(path, vaultKeyBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("encrypted vault key file is missing; run `./scripts/init-vault-key.sh`")
		}
		return nil, fmt.Errorf("encrypted vault key file must be private, regular and contain exactly 32 bytes")
	}
	if len(key) != vaultKeyBytes {
		wipe(key)
		return nil, fmt.Errorf("encrypted vault key file must contain exactly 32 bytes")
	}
	return key, nil
}

func validateCredentials(credentials *garmin.Credentials) error {
	if credentials == nil || credentials.AccessToken == "" || credentials.RefreshToken == "" || credentials.ClientID == "" {
		return fmt.Errorf("Garmin credentials are missing or incomplete")
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private encrypted credential directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("encrypted credential directory is unavailable")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("encrypted credential directory permissions are too open; set the directory to 0700")
	}
	return nil
}

func atomicWritePrivateFile(path string, contents []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".repbridge-credentials-*")
	if err != nil {
		return fmt.Errorf("create encrypted credential vault")
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure encrypted credential file permissions")
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write encrypted credential vault")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync encrypted credential vault")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close encrypted credential vault")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace encrypted credential vault")
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync encrypted credential directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync encrypted credential directory")
	}
	return nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
