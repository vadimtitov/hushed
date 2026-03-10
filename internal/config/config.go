package config

import (
	"os"
	"path/filepath"
)

// Config holds resolved paths for hushed storage.
type Config struct {
	BaseDir string
}

// New resolves the base directory using the following priority:
//  1. $HUSHED_DIR environment variable
//  2. $XDG_DATA_HOME/hushed
//  3. ~/.hushed (default)
func New() (*Config, error) {
	baseDir := resolveBaseDir()
	return &Config{BaseDir: baseDir}, nil
}

func resolveBaseDir() string {
	if d := os.Getenv("HUSHED_DIR"); d != "" {
		return d
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "hushed")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hushed"
	}
	return filepath.Join(home, ".hushed")
}

// KeyPath returns the path to the age identity file.
func (c *Config) KeyPath() string {
	return filepath.Join(c.BaseDir, "key")
}

// SecretsPath returns the path to the encrypted secrets file.
func (c *Config) SecretsPath() string {
	return filepath.Join(c.BaseDir, "secrets.enc")
}

// EnsureDir creates the base directory with 0700 permissions if it doesn't exist.
func (c *Config) EnsureDir() error {
	return os.MkdirAll(c.BaseDir, 0700)
}
