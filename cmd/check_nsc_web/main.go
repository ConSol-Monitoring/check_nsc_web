package main

import (
	"bytes"
	"fmt"
	"os"

	"pkg/checknscweb"
)

func main() {
	output := bytes.NewBuffer(nil)
	rc := checknscweb.Check(output, os.Args[1:])
	fmt.Fprintf(os.Stdout, output.String())
	os.Exit(rc)
}
