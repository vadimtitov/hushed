package redact

import (
	"bytes"
	"strings"
	"testing"
)

// helper: write input in chunks of chunkSize and collect output.
func runRedact(t *testing.T, secrets []string, input string, chunkSize int) string {
	t.Helper()
	var buf bytes.Buffer
	rw := New(&buf, secrets)

	data := []byte(input)
	if chunkSize <= 0 {
		chunkSize = 1
	}
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		n, err := rw.Write(data[:end])
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if n != end {
			t.Fatalf("short write: got %d want %d", n, end)
		}
		data = data[end:]
	}
	if err := rw.Flush(); err != nil {
		t.Fatalf("Flush error: %v", err)
	}
	return buf.String()
}

func TestBasicReplacement(t *testing.T) {
	out := runRedact(t, []string{"hunter2"}, "my password is hunter2", 64)
	if out != "my password is [REDACTED]" {
		t.Errorf("got %q", out)
	}
}

func TestMultipleSecrets(t *testing.T) {
	out := runRedact(t, []string{"alpha", "beta"}, "alpha and beta are secrets", 64)
	if out != "[REDACTED] and [REDACTED] are secrets" {
		t.Errorf("got %q", out)
	}
}

func TestSecretSpanningChunkBoundary(t *testing.T) {
	secret := "SUPERSECRET"
	input := "prefix-" + secret + "-suffix"
	// Use chunk size smaller than the secret to force boundary spanning.
	for chunkSize := 1; chunkSize <= len(secret)+2; chunkSize++ {
		out := runRedact(t, []string{secret}, input, chunkSize)
		expected := "prefix-[REDACTED]-suffix"
		if out != expected {
			t.Errorf("chunkSize=%d: got %q, want %q", chunkSize, out, expected)
		}
	}
}

func TestSecretAppearingMultipleTimes(t *testing.T) {
	out := runRedact(t, []string{"tok"}, "tok tok tok", 64)
	if out != "[REDACTED] [REDACTED] [REDACTED]" {
		t.Errorf("got %q", out)
	}
}

func TestEmptyOutput(t *testing.T) {
	out := runRedact(t, []string{"secret"}, "", 64)
	if out != "" {
		t.Errorf("expected empty, got %q", out)
	}
}

func TestPassthrough(t *testing.T) {
	input := "nothing to redact here"
	out := runRedact(t, []string{"secret"}, input, 64)
	if out != input {
		t.Errorf("got %q", out)
	}
}

func TestNoSecrets(t *testing.T) {
	input := "hello world"
	out := runRedact(t, []string{}, input, 64)
	if out != input {
		t.Errorf("got %q", out)
	}
}

func TestSecretsSubstringsOfEachOther(t *testing.T) {
	// "pass" is a substring of "password"
	secrets := []string{"pass", "password"}
	input := "my password is pass"
	out := runRedact(t, secrets, input, 64)
	// Both should be redacted regardless of order.
	if strings.Contains(out, "pass") {
		t.Errorf("got %q, still contains 'pass'", out)
	}
}

func TestSecretsWithSpecialCharacters(t *testing.T) {
	secret := `p@$$w0rd!#&*()`
	input := "value=" + secret + " end"
	out := runRedact(t, []string{secret}, input, 64)
	if out != "value=[REDACTED] end" {
		t.Errorf("got %q", out)
	}
}

func TestEmptySecretIgnored(t *testing.T) {
	// Empty secrets should be ignored and not cause issues.
	input := "hello world"
	out := runRedact(t, []string{""}, input, 64)
	if out != input {
		t.Errorf("got %q", out)
	}
}

func TestSecretAtStartAndEnd(t *testing.T) {
	out := runRedact(t, []string{"tok"}, "tokXXXtok", 2)
	if out != "[REDACTED]XXX[REDACTED]" {
		t.Errorf("got %q", out)
	}
}

func TestLargeInput(t *testing.T) {
	secret := "mysecret"
	// Build a large string with secrets scattered throughout.
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		if i%10 == 0 {
			sb.WriteString(secret)
		} else {
			sb.WriteString("data")
		}
	}
	input := sb.String()
	out := runRedact(t, []string{secret}, input, 7)
	if strings.Contains(out, secret) {
		t.Error("output still contains secret")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Error("output contains no [REDACTED] markers")
	}
}
