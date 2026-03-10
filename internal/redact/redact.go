package redact

import (
	"bytes"
	"io"
)

const redactedMarker = "[REDACTED]"

// RedactWriter wraps an io.Writer, replacing all occurrences of any secret
// value with "[REDACTED]" before passing data to the underlying writer.
//
// It handles secrets that span chunk boundaries by maintaining a sliding
// window buffer of size (maxSecretLen - 1) bytes. The buffer is kept
// un-flushed until we have enough data to be sure no secret straddles the
// flush boundary.
type RedactWriter struct {
	w       io.Writer
	secrets [][]byte
	maxLen  int
	buf     []byte
}

// New returns a RedactWriter that redacts any of the provided secret values.
// Empty secrets are ignored.
func New(w io.Writer, secrets []string) *RedactWriter {
	var secretBytes [][]byte
	maxLen := 0
	for _, s := range secrets {
		if s == "" {
			continue
		}
		b := []byte(s)
		secretBytes = append(secretBytes, b)
		if len(b) > maxLen {
			maxLen = len(b)
		}
	}
	return &RedactWriter{
		w:       w,
		secrets: secretBytes,
		maxLen:  maxLen,
	}
}

// Write implements io.Writer. It buffers incoming data and flushes all but the
// last (maxLen-1) bytes after redaction. This retains a tail large enough to
// catch any secret that might span the next chunk boundary.
func (rw *RedactWriter) Write(p []byte) (int, error) {
	n := len(p)
	if len(rw.secrets) == 0 {
		_, err := rw.w.Write(p)
		return n, err
	}

	// Append incoming data to the buffer.
	rw.buf = append(rw.buf, p...)

	// Apply redaction to the entire buffer in place.
	rw.buf = redactAll(rw.buf, rw.secrets)

	// Determine how many bytes we can safely flush.
	// We keep the last (maxLen-1) bytes in the buffer because a secret could
	// start in those bytes and complete in the next Write call.
	retain := rw.maxLen - 1
	if retain < 0 {
		retain = 0
	}

	if len(rw.buf) <= retain {
		// Not enough data to safely flush anything yet.
		return n, nil
	}

	flushUntil := len(rw.buf) - retain
	toFlush := rw.buf[:flushUntil]

	if _, err := rw.w.Write(toFlush); err != nil {
		return 0, err
	}

	// Keep only the retained tail.
	remaining := make([]byte, retain)
	copy(remaining, rw.buf[flushUntil:])
	rw.buf = remaining

	return n, nil
}

// Flush writes any remaining buffered data to the underlying writer, applying
// a final redaction pass. Call Flush after the child process exits to drain
// the buffer completely.
func (rw *RedactWriter) Flush() error {
	if len(rw.buf) == 0 {
		return nil
	}
	out := redactAll(rw.buf, rw.secrets)
	rw.buf = rw.buf[:0]
	_, err := rw.w.Write(out)
	return err
}

// redactAll replaces all occurrences of each secret in data with [REDACTED].
func redactAll(data []byte, secrets [][]byte) []byte {
	result := data
	for _, secret := range secrets {
		result = bytes.ReplaceAll(result, secret, []byte(redactedMarker))
	}
	return result
}
