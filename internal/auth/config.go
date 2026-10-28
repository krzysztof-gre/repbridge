package auth

import "os"

// ConfiguredTokenStore opens the encrypted vault shared by Docker commands.
func ConfiguredTokenStore() (CredentialStore, error) {
	path := os.Getenv("REPBRIDGE_TOKEN_FILE")
	if path == "" {
		path = "/data/credentials.enc"
	}
	keyFile := os.Getenv("REPBRIDGE_VAULT_KEY_FILE")
	if keyFile == "" {
		keyFile = "/run/secrets/repbridge-vault-key"
	}
	return NewEncryptedTokenStore(path, keyFile)
}
