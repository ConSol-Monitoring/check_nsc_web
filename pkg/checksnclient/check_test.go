package checksnclient

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

func TestParseEnvironmentVariables(t *testing.T) {
	// The new check_snclient_* names.
	flags := &flagSet{}
	parseEnvironmentVariables(flags, []string{
		"check_snclient_password=newpass",
		"CHECK_SNCLIENT_LOGIN=newlogin",
		"check_snclient_timeout=30",
	})
	assert.Equal(t, "newpass", flags.Password)
	assert.Equal(t, "newlogin", flags.Login)
	assert.Equal(t, "30", flags.Timeout)

	// The deprecated check_nsc_web_* names must keep working.
	flags = &flagSet{}
	parseEnvironmentVariables(flags, []string{
		"check_nsc_web_password=oldpass",
		"CHECK_NSC_WEB_LOGIN=oldlogin",
		"check_nsc_web_timeout=60",
	})
	assert.Equal(t, "oldpass", flags.Password)
	assert.Equal(t, "oldlogin", flags.Login)
	assert.Equal(t, "60", flags.Timeout)
}

func TestBuildRequestTimeoutHeader(t *testing.T) {
	ctx := t.Context()
	buf := &bytes.Buffer{}

	flags := &flagSet{Timeout: "5:UNKNOWN", Password: "secret"}
	req, err := buildRequest(ctx, buf, "https://127.0.0.1:8443/", flags)
	require.NoError(t, err)

	// The new header name is sent, and the legacy name is kept for
	// backwards compatibility with older servers.
	assert.Equal(t, "5.00", req.Header.Get("X-Snclient-Timeout"))
	assert.Equal(t, "5.00", req.Header.Get("X-Nsc-Web-Timeout"))
}
