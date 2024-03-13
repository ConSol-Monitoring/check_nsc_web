package checknscweb

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	ctx := context.TODO()
	buf := &bytes.Buffer{}

	exitCode := Check(ctx, buf, []string{"-h"})
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "Usage:")

	buf.Reset()
	exitCode = Check(ctx, buf, []string{"-p", "password", "-u", "http://localhost:12345", "check_cpu"})
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
}

func TestCheckConfig(t *testing.T) {
	ctx := context.TODO()
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

	exitCode := Check(ctx, buf, []string{"-config", tmpFile})
	assert.Equal(t, 3, exitCode)
	assert.Contains(t, buf.String(), "UNKNOWN")
	assert.Contains(t, buf.String(), "connect:")
}
