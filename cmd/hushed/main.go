package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vadimtitov/hushed/internal/config"
	"github.com/vadimtitov/hushed/internal/runner"
	"github.com/vadimtitov/hushed/internal/store"
)

// version is set via -ldflags at build time.
var version = "dev"

// reservedNames are environment variable names that hushed will never overwrite.
var reservedNames = map[string]bool{
	"PATH":  true,
	"HOME":  true,
	"SHELL": true,
	"USER":  true,
	"PWD":   true,
}

var validName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// validateName normalises and validates a secret name.
// Lowercase letters are uppercased and the user is informed.
func validateName(name string) (string, error) {
	upper := strings.ToUpper(name)
	if upper != name {
		fmt.Fprintf(os.Stderr, "Note: name uppercased to %q\n", upper)
	}
	if !validName.MatchString(upper) {
		return "", fmt.Errorf("invalid name %q: must match [A-Z_][A-Z0-9_]*", upper)
	}
	if reservedNames[upper] {
		return "", fmt.Errorf("name %q is reserved and cannot be used", upper)
	}
	return upper, nil
}

func loadConfig() (*config.Config, error) {
	return config.New()
}

func main() {
	root := &cobra.Command{
		Use:           "hushed",
		Short:         "Keep secrets out of shell output",
		Long:          "hushed — a simple CLI secret manager for LLM agents and automation.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newAddCmd(),
		newRmCmd(),
		newListCmd(),
		newKeysCmd(),
		newRunCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <NAME> [VALUE]",
		Short: "Store a secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := validateName(args[0])
			if err != nil {
				return err
			}

			var value string
			if len(args) == 2 {
				value = args[1]
			} else {
				fmt.Fprint(os.Stderr, "Enter value: ")
				raw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return fmt.Errorf("read password: %w", err)
				}
				value = string(raw)
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			s, err := store.Load(cfg)
			if err != nil {
				return err
			}

			s.Add(name, value)

			if err := s.Save(cfg); err != nil {
				return err
			}

			fmt.Printf("Secret %q stored.\n", name)
			return nil
		},
	}
}

func newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <NAME>",
		Short: "Remove a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := validateName(args[0])
			if err != nil {
				return err
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			s, err := store.Load(cfg)
			if err != nil {
				return err
			}

			if _, ok := s.Get(name); !ok {
				return fmt.Errorf("secret %q not found", name)
			}

			s.Remove(name)

			if err := s.Save(cfg); err != nil {
				return err
			}

			fmt.Printf("Secret %q removed.\n", name)
			return nil
		},
	}
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secret names (never values)",
		Args:  cobra.NoArgs,
		RunE:  runList,
	}
}

func newKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "Alias for list",
		Args:  cobra.NoArgs,
		RunE:  runList,
	}
}

func runList(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	s, err := store.Load(cfg)
	if err != nil {
		return err
	}

	names := s.List()
	if len(names) == 0 {
		fmt.Println("(no secrets stored)")
		return nil
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "run -- <command> [args...]",
		Short:              "Run a command with secrets injected as env vars, redacting output",
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Strip leading "--" separator if present.
			if len(args) > 0 && args[0] == "--" {
				args = args[1:]
			}
			if len(args) == 0 {
				return fmt.Errorf("no command specified after --")
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			s, err := store.Load(cfg)
			if err != nil {
				return err
			}

			err = runner.Run(args, s.All(), os.Stdin, os.Stdout, os.Stderr)
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					os.Exit(exitErr.ExitCode())
				}
				return err
			}
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("hushed", version)
		},
	}
}
