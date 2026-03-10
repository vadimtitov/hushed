package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/vadimtitov/hushed/internal/config"
	"github.com/vadimtitov/hushed/internal/crypto"
)

// secretsFile is the on-disk JSON structure.
type secretsFile struct {
	Secrets map[string]string `json:"secrets"`
}

// Store holds secrets in memory.
type Store struct {
	secrets map[string]string
}

// New returns an empty Store.
func New() *Store {
	return &Store{secrets: make(map[string]string)}
}

// Load reads and decrypts the secrets file. Returns an empty store if the file doesn't exist.
func Load(cfg *config.Config) (*Store, error) {
	s := New()

	path := cfg.SecretsPath()
	encData, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	identity, err := crypto.LoadIdentity(cfg.KeyPath())
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	plaintext, err := crypto.Decrypt(identity, encData)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}

	var sf secretsFile
	if err := json.Unmarshal(plaintext, &sf); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	if sf.Secrets != nil {
		s.secrets = sf.Secrets
	}

	return s, nil
}

// Save encrypts and atomically writes the secrets file.
func (s *Store) Save(cfg *config.Config) error {
	if err := cfg.EnsureDir(); err != nil {
		return fmt.Errorf("ensure dir: %w", err)
	}

	// Load or generate identity.
	identity, err := crypto.LoadIdentity(cfg.KeyPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load identity: %w", err)
		}
		// Key doesn't exist yet; generate it.
		identity, err = crypto.GenerateIdentity(cfg.KeyPath())
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
	}

	sf := secretsFile{Secrets: s.secrets}
	plaintext, err := json.Marshal(sf)
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	encData, err := crypto.Encrypt(identity, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt secrets: %w", err)
	}

	dir := filepath.Dir(cfg.SecretsPath())
	tmp, err := os.CreateTemp(dir, "secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(encData); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, cfg.SecretsPath()); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	if err := os.Chmod(cfg.SecretsPath(), 0600); err != nil {
		return fmt.Errorf("chmod secrets file: %w", err)
	}

	return nil
}

// Add stores a secret.
func (s *Store) Add(name, value string) {
	s.secrets[name] = value
}

// Remove deletes a secret by name.
func (s *Store) Remove(name string) {
	delete(s.secrets, name)
}

// List returns a sorted list of secret names.
func (s *Store) List() []string {
	names := make([]string, 0, len(s.secrets))
	for k := range s.secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Get returns the value for a secret name and whether it exists.
func (s *Store) Get(name string) (string, bool) {
	v, ok := s.secrets[name]
	return v, ok
}

// All returns a copy of the secrets map.
func (s *Store) All() map[string]string {
	m := make(map[string]string, len(s.secrets))
	for k, v := range s.secrets {
		m[k] = v
	}
	return m
}
