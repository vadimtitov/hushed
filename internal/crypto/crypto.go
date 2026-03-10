package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// GenerateIdentity generates a new X25519 age identity and writes it to keyPath.
// The file is created with 0600 permissions.
func GenerateIdentity(keyPath string) (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, identity.String()); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}

	return identity, nil
}

// LoadIdentity reads an age X25519 identity from keyPath.
func LoadIdentity(keyPath string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identity found in key file")
	}

	identity, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("unexpected identity type")
	}

	return identity, nil
}

// Encrypt encrypts data using the identity's recipient (public key).
func Encrypt(identity *age.X25519Identity, data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("create age encrypter: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize encryption: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts data using the provided identity.
func Decrypt(identity *age.X25519Identity, data []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, fmt.Errorf("create age decrypter: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plaintext, nil
}
