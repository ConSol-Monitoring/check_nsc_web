package checknscweb

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

// Original Author 2016 Michael Kraus

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const VERSION = "0.7.0"

const USAGE = `Usage:
  check_nsc_web [options] [query parameters]

Description:
  check_nsc_web is a REST client for the NSClient++/SNClient+ webserver for querying
  and receiving check information over HTTP(S).

Version:
  check_nsc_web v` + VERSION + `

Example:
  connectivity check (parent service):
  check_nsc_web -p "password" -u "https://<SERVER>:8443"

  check without arguments:
  check_nsc_web -p "password" -u "https://<SERVER>:8443" check_cpu

  check with arguments:
  check_nsc_web -p "password" -u "https://<SERVER>:8443" check_drivesize disk=c

Options:
  -u <url>                 SNClient/NSCLient++ URL, for example https://10.1.2.3:8443
  -t <seconds>[:<STATE>]   Connection timeout in seconds. Default: 10sec
                           Optional set timeout state: 0-3 or OK, WARNING, CRITICAL, UNKNOWN
                           (default timeout state is UNKNOWN)
  -e <STATE>               exit code for connection errors. Default is UNKNOWN.
  -a <api version>         API version of SNClient/NSClient++ (legacy or 1) Default: legacy
  -l <username>            REST webserver login. Default: admin
  -p <password>            REST webserver password
  -config <file>           Path to config file

TLS/SSL Options:
  -C <pem file>            Use client certificate (pem) to connect. Must provide -K as well
  -K <key file>            Use client certificate key file to connect
  -ca <pem file>           Use certificate ca to verify server certificate
  -tlsmax <string>         Maximum tls version used to connect
  -tlsmin <string>         Minimum tls version used to connect. Default: tls1.0
  -tlshostname <string>    Use this servername when verifying tls server name
  -k                       Insecure mode - skip TLS verification

Output Options:
  -h                       Print help
  -v                       Enable verbose output
  -vv                      Enable very verbose output (and log directly to stdout)
  -V                       Print program version
  -f <integer>             Round performance data float values to this number of digits. Default: -1
  -j                       Print out JSON response body
  -r                       Print raw result without pre/post processing
  -query <string>          Placeholder for query string from config file
`

// queryV1 represents the json response from snclient in version 1.
type queryV1 struct {
	Command string       `json:"command"`
	Lines   []resultLine `json:"lines"`
	Result  int          `json:"result"`
}

// resultLine is one entry in the result.
type resultLine struct {
	Message string              `json:"message"`
	Perf    map[string]perfLine `json:"perf"`
}

// perfLine represents the nsclient performance data response.
type perfLine struct {
	Value    interface{} `json:"value,omitempty"`
	Unit     *string     `json:"unit,omitempty"`
	Warning  interface{} `json:"warning,omitempty"`
	Critical interface{} `json:"critical,omitempty"`
	Minimum  *float64    `json:"minimum,omitempty"`
	Maximum  *float64    `json:"maximum,omitempty"`
}

// queryLegacy represents the json response from snclient using the legacy version.
type queryLegacy struct {
	Header struct {
		SourceID string `json:"source_id"`
	} `json:"header"`
	Payload []struct {
		Command string `json:"command"`
		Lines   []struct {
			Message string `json:"message"`
			Perf    []struct {
				Alias      string    `json:"alias"`
				IntValue   *perfLine `json:"int_value,omitempty"`
				FloatValue *perfLine `json:"float_value,omitempty"`
			} `json:"perf"`
		} `json:"lines"`
		Result string `json:"result"`
	} `json:"payload"`
}

// toV1 converts a legacy response to version 1.
func (q queryLegacy) toV1() *queryV1 {
	qV1 := new(queryV1)
	if len(q.Payload) == 0 {
		return qV1
	}

	qV1.Command = q.Payload[0].Command
	qV1.Result = naemonState(q.Payload[0].Result)
	qV1.Lines = make([]resultLine, 0)

	for _, line := range q.Payload[0].Lines {
		qV1.Lines = append(qV1.Lines, resultLine{
			Message: line.Message,
		})

		for _, entry := range line.Perf {
			perfL := map[string]perfLine{}

			switch {
			case entry.FloatValue != nil:
				perfL[entry.Alias] = *entry.FloatValue
			case entry.IntValue != nil:
				perfL[entry.Alias] = *entry.IntValue
			default:
				continue
			}

			qV1.Lines = append(qV1.Lines, resultLine{
				Perf: perfL,
			})
		}
	}

	return qV1
}

type flagSet struct {
	URL           string
	Login         string
	Password      string
	APIVersion    string
	Timeout       string
	ErrorExit     string
	Verbose       bool
	VeryVerbose   bool
	JSON          bool
	RawOutput     bool
	Version       bool
	TLSMin        string
	TLSMax        string
	TLSServerName string
	TLSCA         string
	Insecure      bool
	ClientCert    string
	ClientKey     string
	Floatround    int
	Extratext     string
	Query         string
	Config        string
}

func Check(ctx context.Context, output io.Writer, osArgs []string) int {
	flags, args := parseFlags(osArgs, output)
	if flags == nil {
		return 3
	}

	timeout, timeoutExit, err := parseTimeout(flags.Timeout)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return 3
	}
	errorExit := naemonState(flags.ErrorExit)

	queryURL, err := buildURL(flags, args)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return 3
	}

	hClient, err := buildHTTPClient(output, flags, timeout)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return 3
	}
	defer hClient.CloseIdleConnections()

	req, err := buildRequest(ctx, output, queryURL.String(), flags)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return 3
	}

	res, err := hClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			fmt.Fprintf(output, "%s - check timed out after %s ( %s )\n%s",
				naemonName(timeoutExit), timeout.String(), flags.URL, err.Error())

			return timeoutExit
		}

		// clean parameters from error message
		msg := err.Error()
		msg = regexp.MustCompile(`("https?://.*?)/[^"]*"`).ReplaceAllString(msg, "$1/...")

		fmt.Fprintf(output, "%s - %s", naemonName(errorExit), msg)

		return errorExit
	}

	if flags.Verbose {
		dumpres, err2 := httputil.DumpResponse(res, true)
		if err2 != nil {
			fmt.Fprintf(output, "RESPONSE-ERROR: %s\n", err2.Error())
		}

		fmt.Fprintf(output, "<<<<<<RESPONSE:\n%s\n<<<<<<\n", dumpres)
	}

	log.SetOutput(io.Discard)
	contents, err := extractHTTPResponse(res)
	if err != nil {
		fmt.Fprintf(output, "RESPONSE-ERROR: %s\n", err.Error())

		return errorExit
	}

	if flags.RawOutput {
		fmt.Fprintf(output, "\n%s", contents)

		switch res.StatusCode {
		case http.StatusOK:
			return 0
		default:
			return errorExit
		}
	}

	// check http status code
	// getting 403 here means we're not allowed on the target (e.g. allowed hosts)
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(output, "%s - HTTP %s", naemonName(errorExit), res.Status)

		return errorExit
	}

	if len(args) == 0 {
		fmt.Fprintf(output, "OK - REST API reachable on %s", flags.URL)

		if flags.JSON {
			fmt.Fprintf(output, "\n%s", contents)
		}

		return 0
	}

	queryResult, err := extractResult(output, flags, contents)
	if err != nil {
		fmt.Fprintf(output, "%s - %s", naemonName(errorExit), err.Error())

		return errorExit
	}

	if flags.JSON {
		jsonStr, err := json.Marshal(queryResult)
		if err != nil {
			fmt.Fprintf(output, "%s - json error: %s", naemonName(errorExit), err.Error())

			return errorExit
		}

		fmt.Fprintf(output, "%s", jsonStr)

		return 0
	}

	return sendOutput(output, flags, queryResult)
}

func extractHTTPResponse(response *http.Response) (contents []byte, err error) {
	contents, err = io.ReadAll(response.Body)
	if err != nil {
		return
	}

	_, err = io.Copy(io.Discard, response.Body)
	if err != nil {
		return
	}

	response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request failed: %s", response.Status)
	}

	return
}

func parseTLSVersion(version string) (uint16, error) {
	switch strings.ToLower(version) {
	case "":
		return 0, nil
	case "tls10", "tls1.0":
		return tls.VersionTLS10, nil
	case "tls11", "tls1.1":
		return tls.VersionTLS11, nil
	case "tls12", "tls1.2":
		return tls.VersionTLS12, nil
	case "tls13", "tls1.3":
		return tls.VersionTLS13, nil
	default:
		err := fmt.Errorf("cannot parse %s into tls version, supported values are: tls1.0, tls1.1, tls1.2, tls1.3", version)

		return 0, err
	}
}

func getTLSClientConfig(output io.Writer, flags *flagSet) (cfg *tls.Config, err error) {
	cfg = &tls.Config{
		InsecureSkipVerify: flags.Insecure, //nolint:gosec // may be true, but default is false
	}

	tlsMin := uint16(tls.VersionTLS10)
	if flags.TLSMin != "" {
		tlsMin, err = parseTLSVersion(flags.TLSMin)
		if err != nil {
			return nil, fmt.Errorf("tlsmin: %s", err.Error())
		}
	}

	cfg.MinVersion = tlsMin

	tlsMax := uint16(0)
	if flags.TLSMax != "" {
		tlsMax, err = parseTLSVersion(flags.TLSMax)
		if err != nil {
			return nil, fmt.Errorf("tlsmax: %s", err.Error())
		}
	}

	cfg.MaxVersion = tlsMax

	if flags.ClientCert != "" {
		if flags.ClientKey == "" {
			return nil, fmt.Errorf("-K is required when using -C")
		}

		cer, err := tls.LoadX509KeyPair(flags.ClientCert, flags.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("tls.LoadX509KeyPair %s / %s: %w", flags.ClientCert, flags.ClientKey, err)
		}

		cfg.Certificates = []tls.Certificate{cer}

		if flags.Verbose {
			fmt.Fprintf(output, "using client cert: %s\n", flags.ClientCert)
			fmt.Fprintf(output, "using client key:  %s\n", flags.ClientKey)
		}
	}

	if flags.TLSCA != "" {
		caCert, err := os.ReadFile(flags.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("readfile %s: %w", flags.TLSCA, err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		cfg.RootCAs = caCertPool

		if flags.Verbose {
			fmt.Fprintf(output, "using ca: %s\n", flags.TLSCA)
		}
	}

	cfg.ServerName = flags.TLSServerName

	return cfg, nil
}

func parseFlags(osArgs []string, output io.Writer) (flags *flagSet, args []string) {
	flags = &flagSet{}
	flagSet := flag.NewFlagSet("check_nsc_web", flag.ContinueOnError)
	flagSet.SetOutput(output)
	flagSet.StringVar(&flags.URL, "u", "", "SNClient URL, for example https://10.1.2.3:8443")
	flagSet.StringVar(&flags.Login, "l", "admin", "SNClient webserver login")
	flagSet.StringVar(&flags.Password, "p", "", "SNClient webserver password")
	flagSet.StringVar(&flags.APIVersion, "a", "legacy", "API version of SNClient (legacy or 1)")
	flagSet.StringVar(&flags.Timeout, "t", "10:UNKNOWN", "Connection timeout in seconds")
	flagSet.StringVar(&flags.ErrorExit, "e", "UNKNOWN", "Connection error exit code.")
	flagSet.BoolVar(&flags.Verbose, "v", false, "Enable verbose output")
	flagSet.BoolVar(&flags.VeryVerbose, "vv", false, "Enable very verbose output (and log directly to stdout)")
	flagSet.BoolVar(&flags.JSON, "j", false, "Print out JSON response body")
	flagSet.BoolVar(&flags.RawOutput, "r", false, "Print raw result without pre/post processing")
	flagSet.BoolVar(&flags.Version, "V", false, "Print program version")
	flagSet.BoolVar(&flags.Insecure, "k", false, "Insecure mode - skip TLS verification")
	flagSet.StringVar(&flags.TLSMin, "tlsmin", "tls1.0", "Minimum tls version used to connect")
	flagSet.StringVar(&flags.TLSMax, "tlsmax", "", "Maximum tls version used to connect")
	flagSet.StringVar(&flags.TLSServerName, "tlshostname", "", "Use this servername when verifying tls server name")
	flagSet.StringVar(&flags.ClientCert, "C", "", "Use client certificate (pem) to connect. Must provide -K as well")
	flagSet.StringVar(&flags.ClientKey, "K", "", "Use client certificate key file to connect")
	flagSet.StringVar(&flags.TLSCA, "ca", "", "Use certificate ca to verify server certificate")
	flagSet.IntVar(&flags.Floatround, "f", -1, "Round performance data float values to this number of digits")
	flagSet.StringVar(&flags.Config, "config", "", "Path to config file")
	flagSet.Usage = func() {
		fmt.Fprintf(output, "%s", USAGE)
	}

	flagSet.StringVar(&flags.Query, "query", "", "placeholder for query string from config file")

	err := flagSet.Parse(osArgs)
	if errors.Is(err, flag.ErrHelp) {
		return nil, nil
	}

	if flags.VeryVerbose {
		flags.Verbose = true
		output = os.Stdout
	}

	if flags.Version {
		fmt.Fprintf(output, "check_nsc_web v%s", VERSION)

		return nil, nil
	}

	if flags.Config != "" {
		err := parseFlagsFromFile(output, flags, flagSet, flags.Config)
		if err != nil {
			fmt.Fprintf(output, "failed to parse config file: %s\n", err.Error())

			return nil, nil
		}
	}

	if flags.URL == "" {
		fmt.Fprintf(output, "UNKNOWN - missing required -u argument\n")
		flagSet.Usage()

		return nil, nil
	}

	if flags.Password == "" {
		fmt.Fprintf(output, "UNKNOWN - missing required -p argument\n")
		flagSet.Usage()

		return nil, nil
	}

	args = flagSet.Args()
	// Has there a flag "query" been provided in the config file? Transform it into slice and append it to Args()
	if flags.Query != "" {
		q := strings.Split(flags.Query, " ")
		args = append(args, q...)
	}

	return flags, args
}

// parseFlagsFromFile parses flags from the file in path.
// Same format as commandline argumens, newlines and lines beginning with a
// "#" charater are ignored. Flags already set will be ignored.
// converted fro namsral/flag.
func parseFlagsFromFile(output io.Writer, flags *flagSet, flagSet *flag.FlagSet, path string) error {
	// Extract arguments from file
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %s", err.Error())
	}
	defer file.Close()

	seen := map[string]bool{}
	flagSet.Visit(func(flag *flag.Flag) {
		seen[flag.Name] = true
	})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Ignore empty lines
		if line == "" {
			continue
		}

		// Ignore comments
		if line[:1] == "#" {
			continue
		}

		// Match `key=value` and `key value`
		var name, value string
		hasValue := false
		for i, v := range line {
			if v == '=' || v == ' ' {
				hasValue = true
				name, value = line[:i], line[i+1:]

				break
			}
		}

		if !hasValue {
			name = line
		}

		// Ignore flagVal when already set; arguments have precedence over file
		flagVal := flagSet.Lookup(name)
		if flagVal == nil {
			return fmt.Errorf("variable provided but not defined: %s", name)
		}
		if _, ok := seen[name]; ok {
			if flags.Verbose {
				fmt.Fprintf(output, "flag %s already set from commandline, skipping config file value\n", name)
			}

			continue
		}

		// hack to determine if flag is boolean
		if strings.Contains(fmt.Sprintf("%#v", flagVal.Value), "flag.boolValue") { // special case: doesn't need an arg
			if !hasValue {
				// flag without value is a true bool
				value = "true"
			}
			if err := flagVal.Value.Set(value); err != nil {
				return fmt.Errorf("invalid boolean value %q for configuration variable %s: %s", value, name, err.Error())
			}
		} else {
			if err := flagVal.Value.Set(value); err != nil {
				return fmt.Errorf("invalid value %q for configuration variable %s: %s", value, name, err.Error())
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to parse config file: %s", err.Error())
	}

	return nil
}

func sendOutput(output io.Writer, flags *flagSet, queryResult *queryV1) int {
	nagiosMessage := ""
	nagiosPerfdata := []string{}

	for _, line := range queryResult.Lines {
		nagiosMessage += strings.TrimSpace(line.Message)

		// iterate by sorted sortedPerfLabel, otherwise the order of performance label is different every time
		sortedPerfLabel := make([]string, 0, len(line.Perf))

		for k := range line.Perf {
			sortedPerfLabel = append(sortedPerfLabel, k)
		}

		sort.Strings(sortedPerfLabel)

		for _, perfName := range sortedPerfLabel {
			perf := line.Perf[perfName]
			// REFERENCE 'label'=value[UOM];[warn];[crit];[min];[max]
			var (
				val string
				uni string
				war string
				cri string
				min string
				max string
			)

			if perf.Value != nil {
				switch perfVal := perf.Value.(type) {
				case float64:
					val = strconv.FormatFloat(perfVal, 'f', flags.Floatround, 64)
				case string:
					val = perfVal
				default:
					fmt.Fprintf(output, "UNKNOWN - json error: unknown value type: %T", perfVal)
				}
			} else {
				continue
			}

			if perf.Unit != nil {
				uni = (*(perf.Unit))
			}

			if perf.Warning != nil {
				war = fmt.Sprintf("%v", perf.Warning)
			}

			if perf.Critical != nil {
				cri = fmt.Sprintf("%v", perf.Critical)
			}

			if perf.Minimum != nil {
				min = strconv.FormatFloat(*(perf.Minimum), 'f', flags.Floatround, 64)
			}

			if perf.Maximum != nil {
				max = strconv.FormatFloat(*(perf.Maximum), 'f', flags.Floatround, 64)
			}

			nagiosPerfdata = append(nagiosPerfdata, fmt.Sprintf("'%s'=%s%s;%s;%s;%s;%s", perfName, val, uni, war, cri, min, max))
		}
	}

	if len(nagiosPerfdata) == 0 {
		fmt.Fprintf(output, "%s %s", nagiosMessage, flags.Extratext)
	} else {
		fmt.Fprintf(output, "%s %s|%s", nagiosMessage, flags.Extratext, strings.TrimSpace(strings.Join(nagiosPerfdata, " ")))
	}

	return (queryResult.Result)
}

func buildHTTPClient(output io.Writer, flags *flagSet, timeout time.Duration) (*http.Client, error) {
	tlsConfig, err := getTLSClientConfig(output, flags)
	if err != nil {
		return nil, err
	}

	hTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial: (&net.Dialer{
			Timeout: timeout,
		}).Dial,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		IdleConnTimeout:       timeout,
	}
	hClient := &http.Client{
		Timeout:   timeout,
		Transport: hTransport,
	}

	return hClient, nil
}

func extractResult(output io.Writer, flags *flagSet, contents []byte) (*queryV1, error) {
	queryResult := &queryV1{}
	if flags.APIVersion == "1" {
		err := json.Unmarshal(contents, &queryResult)
		if err != nil {
			return nil, fmt.Errorf("json error: %s", err.Error())
		}

		return queryResult, nil
	}

	queryLeg := &queryLegacy{}
	err := json.Unmarshal(contents, &queryLeg)
	if err != nil {
		return nil, fmt.Errorf("json error: %s", err.Error())
	}

	if len(queryLeg.Payload) == 0 {
		if flags.Verbose {
			fmt.Fprintf(output, "QUERY RESULT:\n%+v\n", queryLeg)
		}

		return nil, fmt.Errorf("resultpayload size is 0")
	}

	return queryLeg.toV1(), nil
}

func buildURL(flags *flagSet, args []string) (*url.URL, error) {
	urlStruct, err := url.Parse(flags.URL)
	if err != nil {
		return nil, fmt.Errorf("url.Parse: %s", err.Error())
	}

	switch {
	case flags.RawOutput:
		if len(args) > 0 {
			return nil, fmt.Errorf("no arguments supported in passthrough mode")
		}
	case len(args) == 0:
		if !strings.HasSuffix(urlStruct.Path, "/") {
			urlStruct.Path += "/"
		}
	default:
		if flags.APIVersion == "1" {
			urlStruct.Path += "/api/v1/queries/" + args[0] + "/commands/execute"
		} else {
			urlStruct.Path += "/query/" + args[0]
		}
	}

	if len(args) > 1 {
		urlStruct.RawQuery = buildQueryString(args)
	}

	return urlStruct, nil
}

func naemonName(state int) string {
	switch state {
	case 0:
		return "OK"
	case 1:
		return "WARNING"
	case 2:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func naemonState(state string) int {
	switch strings.ToLower(state) {
	case "ok", "0":
		return 0
	case "warning", "1":
		return 1
	case "critical", "2":
		return 2
	default:
		return 3
	}
}

func parseTimeout(flagTimeout string) (timeout time.Duration, timeoutExit int, err error) {
	timeout = 10 * time.Second
	timeoutExit = 3
	if flagTimeout != "" {
		fields := strings.Split(flagTimeout, ":")
		if len(fields) > 1 {
			timeoutExit = naemonState(fields[1])
		}
		sec, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, 0, fmt.Errorf("cannot parse timeout: %s", err.Error())
		}
		timeout = time.Second * time.Duration(sec)
	}

	return
}

func buildQueryString(args []string) string {
	var param strings.Builder
	for i, arg := range args {
		if i == 0 {
			continue
		} else if i > 1 {
			param.WriteString("&")
		}

		p := strings.SplitN(arg, "=", 2)
		if len(p) == 1 {
			param.WriteString(url.QueryEscape(p[0]))
		} else {
			param.WriteString(url.QueryEscape(p[0]) + "=" + url.QueryEscape(p[1]))
		}
	}

	return param.String()
}

func buildRequest(ctx context.Context, output io.Writer, query string, flags *flagSet) (req *http.Request, err error) {
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, query, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request: %s", err.Error())
	}

	if flags.APIVersion == "1" && flags.Login != "" {
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(flags.Login+":"+flags.Password)))
	} else {
		req.Header.Add("password", flags.Password)
	}

	if flags.Verbose {
		dumpreq, err2 := httputil.DumpRequestOut(req, true)
		if err2 != nil {
			fmt.Fprintf(output, "REQUEST-ERROR:\n%s\n", err2.Error())
		}

		fmt.Fprintf(output, ">>>>>>REQUEST:\n%s\n>>>>>>\n", dumpreq)
	}

	return req, nil
}
