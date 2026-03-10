package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/vti/hushed/internal/redact"
)

// Run executes cmd[0] with args cmd[1:], injecting secrets as environment
// variables. stdout and stderr of the child process are streamed through
// RedactWriters that replace secret values with [REDACTED].
//
// Signals SIGINT and SIGTERM are forwarded to the child process.
// The child's exit code is preserved via exec.ExitError.
func Run(cmd []string, secrets map[string]string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(cmd) == 0 {
		return fmt.Errorf("no command specified")
	}

	secretValues := make([]string, 0, len(secrets))
	for _, v := range secrets {
		secretValues = append(secretValues, v)
	}

	rStdout := redact.New(stdout, secretValues)
	rStderr := redact.New(stderr, secretValues)

	c := exec.Command(cmd[0], cmd[1:]...) //nolint:gosec
	c.Env = buildEnv(secrets)
	c.Stdin = stdin
	c.Stdout = rStdout
	c.Stderr = rStderr

	if err := c.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	// Forward signals to child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if c.Process != nil {
				_ = c.Process.Signal(sig)
			}
		}
	}()

	err := c.Wait()

	signal.Stop(sigCh)
	close(sigCh)

	// Flush any remaining buffered data.
	_ = rStdout.Flush()
	_ = rStderr.Flush()

	return err
}

// buildEnv constructs the environment for the child process. It starts with
// the current process environment and overlays the provided secrets.
func buildEnv(secrets map[string]string) []string {
	env := os.Environ()
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}
	return env
}
