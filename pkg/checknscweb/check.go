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
	"strconv"
	"strings"
	"time"

	"github.com/namsral/flag"
)

const VERSION = "0.6.0"

var usage = `
  check_nsc_web is a REST client for the NSClient++/SNClient+ webserver for querying
  and receiving check information over HTTPS.

  Example:
  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu

  Usage:
  check_nsc_web [options] [query parameters]

  check_nsc_web can and should be built with CGO_ENABLED=0

  Options:
`

// Query represents the nsclient response, which itself decomposes in lines in
// which there may be several performance data.
type PerfLine struct {
	Value    *float64    `json:"value,omitempty"`
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
	qV1.Lines = make([]ResultLine, len(q.Payload[0].Lines))

	for lineNr, line := range q.Payload[0].Lines {
		qV1.Lines[lineNr].Message = line.Message
		qV1.Lines[lineNr].Perf = make(map[string]PerfLine)

		for _, p := range line.Perf {
			if p.FloatValue != nil {
				qV1.Lines[lineNr].Perf[p.Alias] = *p.FloatValue
			} else {
				qV1.Lines[lineNr].Perf[p.Alias] = *p.IntValue
			}
		}
	}

	return qV1
}

var (
	flagURL        string
	flagLogin      string
	flagPassword   string
	flagAPIVersion string
	flagTimeout    int
	flagVerbose    bool
	flagJSON       bool
	flagVersion    bool
	flagTLSMin     string
	flagTLSMax     string
	flagInsecure   bool
	flagFloatround int
	flagExtratext  string
	flagQuery      string
)

func Check(ctx context.Context, output io.Writer, osArgs []string) int {
	flags := flag.NewFlagSet("check_nsc_web", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&flagURL, "u", "", "NSCLient++ URL, for example https://10.1.2.3:8443.")
	flags.StringVar(&flagLogin, "l", "admin", "NSClient++ webserver login.")
	flags.StringVar(&flagPassword, "p", "", "NSClient++ webserver password.")
	flags.StringVar(&flagAPIVersion, "a", "legacy", "API version of NSClient++ (legacy or 1).")
	flags.IntVar(&flagTimeout, "t", 10, "Connection timeout in seconds.")
	flags.BoolVar(&flagVerbose, "v", false, "Enable verbose output.")
	flags.BoolVar(&flagJSON, "j", false, "Print out JSON response body.")
	flags.BoolVar(&flagVersion, "V", false, "Print program version.")
	flags.BoolVar(&flagInsecure, "k", false, "Insecure mode - skip TLS verification.")
	flags.StringVar(&flagTLSMin, "tlsmin", "tls1.0", "Minimum tls version used to connect.")
	flags.StringVar(&flagTLSMax, "tlsmax", "", "Maximum tls version used to connect.")
	flags.IntVar(&flagFloatround, "f", -1, "Round performance data float values to this number of digits.")
	flags.Usage = func() {
		fmt.Fprintf(output, "check_nsc_web v%s", VERSION)
		fmt.Fprintf(output, "%s", usage)
		flags.PrintDefaults()
	}

	// These flags support loading config from file using "-config FILENAME"
	flags.StringVar(&flagQuery, "query", "", "placeholder for query string from config file")
	flags.String(flag.DefaultConfigFlagname, "", "path to config file")

	err := flags.Parse(osArgs)
	if errors.Is(err, flag.ErrHelp) {
		return (3)
	}

	if flagVersion {
		fmt.Fprintf(output, "check_nsc_web v%s", VERSION)

		return (3)
	}

	seen := make(map[string]bool)

	flags.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})

	for _, req := range []string{"u", "p"} {
		if !seen[req] {
			fmt.Fprintf(output, "UNKNOWN: Missing required -%s argument\n", req)
			fmt.Fprintf(output, "Usage of check_nsc_web:\n")
			flags.Usage()

			return (3)
		}
	}

	args := flags.Args()
	// Has there a flag "query" been provided in the config file? Transform it into slice and append it to Args()
	if seen["query"] {
		q := strings.Split(flagQuery, " ")
		args = append(args, q...)
	}

	timeout := time.Second * time.Duration(flagTimeout)

	urlStruct, err := url.Parse(flagURL)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN: %s", err.Error())

		return (3)
	}

	if len(args) == 0 {
		urlStruct.Path += "/"
	} else {
		if flagAPIVersion == "1" {
			urlStruct.Path += "/api/v1/queries/" + args[0] + "/commands/execute"
		} else {
			urlStruct.Path += "/query/" + args[0]
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
					fmt.Fprintf(output, "UNKNOWN: %s", err.Error())

					return (3)
				}
			}
			urlStruct.RawQuery = param.String()
		}
	}

	tlsMin := uint16(tls.VersionTLS10)
	if flagTLSMin != "" {
		tlsMin, err = parseTLSVersion(flagTLSMin)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN: -tlsmin: %s", err.Error())

			return (3)
		}
	}

	tlsMax := uint16(0)
	if flagTLSMax != "" {
		tlsMax, err = parseTLSVersion(flagTLSMax)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN: -tlsmax: %s", err.Error())

			return (3)
		}
	}

	hTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tlsMin,
			MaxVersion:         tlsMax,
			InsecureSkipVerify: flagInsecure,
		},
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
		fmt.Fprintf(output, "UNKNOWN: %s", err.Error())

		return (3)
	}

	if flagAPIVersion == "1" && flagLogin != "" {
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(flagLogin+":"+flagPassword)))
	} else {
		req.Header.Add("password", flagPassword)
	}

	if flagVerbose {
		dumpreq, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Fprintf(output, "REQUEST-ERROR:\n%s\n", err.Error())
		}

		fmt.Fprintf(output, "REQUEST:\n%q\n", dumpreq)
	}

	res, err := hClient.Do(req)
	if err != nil {
		fmt.Fprintf(output, "UNKNOWN: %s", err.Error())

		return (3)
	}

	// check http status code
	// getting 403 here means we're not allowed on the target (e.g. allowed hosts)
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(output, "UNKNOWN: HTTP %s", res.Status)

		return (3)
	}

	if flagVerbose {
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

	if len(args) == 0 {
		fmt.Fprintf(output, "OK: NSClient API reachable on %s", flagURL)

		return (0)
	}

	queryResult := new(QueryV1)
	if flagAPIVersion == "1" {
		err = json.Unmarshal(contents, &queryResult)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN: json error: %s", err.Error())

			return (3)
		}
	} else {
		queryLeg := new(QueryLeg)
		err = json.Unmarshal(contents, &queryLeg)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN: json error: %s", err.Error())

			return (3)
		}

		if len(queryLeg.Payload) == 0 {
			if flagVerbose {
				fmt.Fprintf(output, "QUERY RESULT:\n%+v\n", queryLeg)
			}
			fmt.Fprintf(output, "UNKNOWN: The resultpayload size is 0")

			return (3)
		}
		queryResult = queryLeg.toV1()
	}

	if flagJSON {
		jsonStr, err := json.Marshal(queryResult)
		if err != nil {
			fmt.Fprintf(output, "UNKNOWN: json error: %s", err.Error())

			return (3)
		}

		fmt.Fprintf(output, "%s", jsonStr)

		return (0)
	}

	nagiosMessage := ""
	nagiosPerfdata := &bytes.Buffer{}

	for _, l := range queryResult.Lines {
		nagiosMessage = strings.TrimSpace(l.Message)

		for perfName, perf := range l.Perf {
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
				val = strconv.FormatFloat(*(perf.Value), 'f', flagFloatround, 64)
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
				min = strconv.FormatFloat(*(perf.Minimum), 'f', flagFloatround, 64)
			}

			if perf.Maximum != nil {
				max = strconv.FormatFloat(*(perf.Maximum), 'f', flagFloatround, 64)
			}

			fmt.Fprintf(nagiosPerfdata, "'%s'=%s%s;%s;%s;%s;%s", perfName, val, uni, war, cri, min, max)
		}
	}

	if nagiosPerfdata.Len() == 0 {
		fmt.Fprintf(output, "%s %s", nagiosMessage, flagExtratext)
	} else {
		fmt.Fprintf(output, "%s %s|%s", nagiosMessage, flagExtratext, strings.TrimSpace(nagiosPerfdata.String()))
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
