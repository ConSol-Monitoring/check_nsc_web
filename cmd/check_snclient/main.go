package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/consol-monitoring/check_snclient/pkg/checksnclient"
)

func main() {
	output := bytes.NewBuffer(nil)
	rc := checksnclient.Check(context.Background(), output, os.Args[1:], os.Environ())
	res := strings.TrimSpace(output.String())
	fmt.Fprintf(os.Stdout, "%s\n", res)
	os.Exit(rc)
}
