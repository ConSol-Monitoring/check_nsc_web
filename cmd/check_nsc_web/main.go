package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/consol-monitoring/check_nsc_web/pkg/checknscweb"
)

func main() {
	output := bytes.NewBuffer(nil)
	rc := checknscweb.Check(context.Background(), output, os.Args[1:])
	res := strings.TrimSpace(output.String())
	fmt.Fprintf(os.Stdout, "%s\n", res)
	os.Exit(rc)
}
