package checknscweb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}

	exitCode := Check(ctx, buf, []string{"-h"}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "Usage:")

	buf.Reset()
	exitCode = Check(ctx, buf, []string{"-p", "password", "-u", "http://localhost:12345", "check_cpu"}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
	assert.NotContains(t, buf.String(), "check_cpu")
}

func TestCheckConfig(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}
	tmpFile := filepath.Join(t.TempDir(), "config")

	config := `
# test config file
k true
p password
u https://127.0.0.1:12345
query check_cpu show-all
`
	err := os.WriteFile(tmpFile, []byte(config), 0o600)
	require.NoError(t, err)

	exitCode := Check(ctx, buf, []string{"-config", tmpFile}, nil)
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
	assert.NotContains(t, buf.String(), "check_cpu")
}

func TestFormatPerfValue(t *testing.T) {
	// Integer values must not be rounded or padded with decimals.
	assert.Equal(t, "10", formatPerfValue(10, 2))
	assert.Equal(t, "10", formatPerfValue(10, -1))

	// Float values are rounded to the configured number of digits.
	assert.Equal(t, "10.50", formatPerfValue(10.5, 2))
	assert.Equal(t, "10.5", formatPerfValue(10.5, -1))
	assert.Equal(t, "12.35", formatPerfValue(12.3456, 2))
}
