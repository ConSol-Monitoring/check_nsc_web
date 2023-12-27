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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/namsral/flag"
)

const VERSION = "0.6.2"

const usage = `Usage:
  check_nsc_web [options] [query parameters]

Description:
  check_nsc_web is a REST client for the NSClient++/SNClient+ webserver for querying
  and receiving check information over HTTPS.

Version:
  check_nsc_web v` + VERSION + `

Example:
  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu

  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_drivesize disk=c

Options:
  -u <url>                 SNClient/NSCLient++ URL, for example https://10.1.2.3:8443
  -t <seconds>             Connection timeout in seconds. Default: 10
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
  -V                       Print program version
  -f <integer>             Round performance data float values to this number of digits. Default: -1
  -j                       Print out JSON response body
  -r                       Print raw result without pre/post processing
  -query <string>          Placeholder for query string from config file
`

// Query represents the nsclient response, which itself decomposes in lines in
// which there may be several performance data.
type PerfLine struct {
	Value    interface{} `json:"value,omitempty"`
	Unit     *string     `json:"unit,omitempty"`
	Warning  interface{} `json:"warning,omitempty"`
	Critical interface{} `json:"critical,omitempty"`
	Minimum  *float64    `json:"minimum,omitempty"`
	Maximum  *float64    `json:"maximum,omitempty"`
}

type ResultLine struct {
	Message string              `json:"message"`
	Perf    map[string]PerfLine `json:"perf"`
}

// Query type depends on API version (v1 or legacy).
type QueryV1 struct {
	Command string       `json:"command"`
	Lines   []ResultLine `json:"lines"`
	Result  int          `json:"result"`
}

type QueryLeg struct {
	Header struct {
		SourceID string `json:"source_id"`
	} `json:"header"`
	Payload []struct {
		Command string `json:"command"`
		Lines   []struct {
			Message string `json:"message"`
			Perf    []struct {
				Alias      string    `json:"alias"`
				IntValue   *PerfLine `json:"int_value,omitempty"`
				FloatValue *PerfLine `json:"float_value,omitempty"`
			} `json:"perf"`
		} `json:"lines"`
		Result string `json:"result"`
	} `json:"payload"`
}

var ReturncodeMap = map[string]int{
	"OK":       0,
	"WARNING":  1,
	"CRITICAL": 2,
	"UNKNOWN":  3,
}

func (q QueryLeg) toV1() *QueryV1 {
	qV1 := new(QueryV1)
	if len(q.Payload) == 0 {
		return qV1
	}

	qV1.Command = q.Payload[0].Command
	qV1.Result = ReturncodeMap[q.Payload[0].Result]
	qV1.Lines = make([]ResultLine, 0)

	for _, line := range q.Payload[0].Lines {
		qV1.Lines = append(qV1.Lines, ResultLine{
			Message: line.Message,
		})

		for _, p := range line.Perf {
			perfL := map[string]PerfLine{}
			if p.FloatValue != nil {
				perfL[p.Alias] = *p.FloatValue
			} else {
				perfL[p.Alias] = *p.IntValue
			}

			qV1.Lines = append(qV1.Lines, ResultLine{
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
	Timeout       int
	Verbose       bool
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
}

func Check(ctx context.Context, output io.Writer, osArgs []string) int {
	flags := flagSet{}
	flagSet := flag.NewFlagSet("check_nsc_web", flag.ContinueOnError)
	flagSet.SetOutput(output)
	flagSet.StringVar(&flags.URL, "u", "", "SNClient URL, for example https://10.1.2.3:8443")
	flagSet.StringVar(&flags.Login, "l", "admin", "SNClient webserver login")
	flagSet.StringVar(&flags.Password, "p", "", "SNClient webserver password")
	flagSet.StringVar(&flags.APIVersion, "a", "legacy", "API version of SNClient (legacy or 1)")
	flagSet.IntVar(&flags.Timeout, "t", 10, "Connection timeout in seconds")
	flagSet.BoolVar(&flags.Verbose, "v", false, "Enable verbose output")
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
	flagSet.Usage = func() {
		fmt.Fprintf(output, "%s", usage)
	}

	// These flags support loading config from file using "-config FILENAME"
	flagSet.StringVar(&flags.Query, "query", "", "placeholder for query string from config file")
	flagSet.String(flag.DefaultConfigFlagname, "", "path to config file")

	err := flagSet.Parse(osArgs)
	if errors.Is(err, flag.ErrHelp) {
		return (3)
	}

	if flags.Version {
		fmt.Fprintf(output, "check_nsc_web v%s", VERSION)

		return (3)
	}

	seen := make(map[string]bool)

	flagSet.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})

	for _, req := range []string{"u", "p"} {
		if !seen[req] {
			fmt.Fprintf(output, "UNKNOWN - missing required -%s argument\n", req)
			flagSet.Usage()

			return (3)
		}
	}

	args := flagSet.Args()
	// Has there a flag "query" been provided in the config file? Transform it into slice and append it to Args()
	if seen["query"] {
		q := strings.Split(flags.Query, " ")
		args = append(args, q...)
	}

	timeout := time.Second * time.Duration(flags.Timeout)

	urlStruct, err := url.Parse(flags.URL)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return (3)
	}

	switch {
	case flags.RawOutput:
		if len(args) > 0 {
			fmt.Fprintf(output, "UNKNOWN - no arguments supported in passthrough mode")

			return (3)
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
		var param bytes.Buffer

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

			if err != nil {
				fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

				return (3)
			}
		}

		urlStruct.RawQuery = param.String()
	}

	tlsConfig, err := getTLSClientConfig(output, &flags)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return (3)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStruct.String(), http.NoBody)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN - %s", err.Error())

		return (3)
	}

	if flags.APIVersion == "1" && flags.Login != "" {
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(flags.Login+":"+flags.Password)))
	} else {
		req.Header.Add("password", flags.Password)
	}

	if flags.Verbose {
		dumpreq, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Fprintf(output, "REQUEST-ERROR:\n%s\n", err.Error())
		}

		fmt.Fprintf(output, "REQUEST:\n%q\n", dumpreq)
	}

	res, err := hClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			fmt.Fprintf(output, "UNKNOWN - check timed out after %s ( %s )\n%s", timeout.String(), flags.URL, err.Error())
		} else {
			fmt.Fprintf(output, "UNKNOWN - %s", err.Error())
		}

		return (3)
	}

	if flags.Verbose {
		dumpres, err := httputil.DumpResponse(res, true)
		if err != nil {
			fmt.Fprintf(output, "RESPONSE-ERROR: %s\n", err.Error())
		}

		fmt.Fprintf(output, "RESPONSE:\n%q\n", dumpres)
	}

	log.SetOutput(io.Discard)

	contents, err := extractHTTPResponse(res)
	if err != nil {
		fmt.Fprintf(output, "RESPONSE-ERROR: %s\n", err.Error())

		return (3)
	}

	hClient.CloseIdleConnections()

	if flags.RawOutput {
		fmt.Fprintf(output, "\n%s", contents)

		switch res.StatusCode {
		case http.StatusOK:
			return (0)
		default:
			return (3)
		}
	}

	// check http status code
	// getting 403 here means we're not allowed on the target (e.g. allowed hosts)
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(output, "UNKNOWN - HTTP %s", res.Status)

		return (3)
	}

	if len(args) == 0 {
		fmt.Fprintf(output, "OK - REST API reachable on %s", flags.URL)

		if flags.JSON {
			fmt.Fprintf(output, "\n%s", contents)
		}

		return (0)
	}

	queryResult := new(QueryV1)
	if flags.APIVersion == "1" {
		err = json.Unmarshal(contents, &queryResult)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN - json error: %s", err.Error())

			return (3)
		}
	} else {
		queryLeg := new(QueryLeg)
		err = json.Unmarshal(contents, &queryLeg)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN - json error: %s", err.Error())

			return (3)
		}

		if len(queryLeg.Payload) == 0 {
			if flags.Verbose {
				fmt.Fprintf(output, "QUERY RESULT:\n%+v\n", queryLeg)
			}
			fmt.Fprintf(output, "UNKNOWN - The resultpayload size is 0")

			return (3)
		}
		queryResult = queryLeg.toV1()
	}

	if flags.JSON {
		jsonStr, err := json.Marshal(queryResult)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN - json error: %s", err.Error())

			return (3)
		}

		fmt.Fprintf(output, "%s", jsonStr)

		return (0)
	}

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
