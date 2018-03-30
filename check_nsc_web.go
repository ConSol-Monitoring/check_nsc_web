package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TODO
// - specify cert
// - specify ciphers
// -- http://www.levigross.com/2015/11/21/mutual-tls-authentication-in-go/
// -- http://johnnadratowski.github.io/2016/08/05/golang-tls.html

const AppVersion = "0.4.3"

var usage = `
  check_nsc_web is a REST client for the NSClient++ webserver for querying
  and receiving check information over HTTPS.

  Copyright 2016 Michael Kraus <Michael.Kraus@consol.de>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  Example:
  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu

  Usage:
  check_nsc_web [options] [NSClient query parameters]

  check_nsc_web can and should be built with CGO_ENABLED=0

  Options:
`

//Query represents the nsclient response, which itself decomposes in lines in which there may be several performance data
type PerfLine struct {
	Value    *float64 `json:"value,omitempty"`
	Unit     *string  `json:"unit,omitempty"`
	Warning  *float64 `json:"warning,omitempty"`
	Critical *float64 `json:"critical,omitempty"`
	Minimum  *float64 `json:"minimum,omitempty"`
	Maximum  *float64 `json:"maximum,omitempty"`
}

type ResultLine struct {
	Message string `json:"message"`
	Perf	map[string]PerfLine `json:"perf"`
}

//Query type depends on API version (v1 or legacy)
type QueryV1 struct {
	Command string `json:"command"`
	Lines	[]ResultLine `json:"lines"`
	Result string `json:"result"`
}

type QueryLeg struct {
	Header struct {
		SourceID string `json:"source_id"`
	} `json:"header"`
	Payload []struct {
		Command string `json:"command"`
		Lines	[]struct {
			Message string `json:"message"`
			Perf	[]struct {
				Alias	string `json:"alias"`
				IntValue   *PerfLine `json:"int_value,omitempty"`
				FloatValue *PerfLine `json:"float_value,omitempty"`
			} `json:"perf"`
		} `json:"lines"`
		Result string `json:"result"`
	} `json:"payload"`
}

func (q QueryLeg) toV1() *QueryV1 {
	qV1 := new(QueryV1)
	if len(q.Payload) == 0 {
		return qV1
	}
	qV1.Command = q.Payload[0].Command
	qV1.Lines = make([]ResultLine, len(q.Payload[0].Lines))
	for i, v := range(q.Payload[0].Lines) {
		qV1.Lines[i].Perf = make(map[string]PerfLine)
		for _, p := range(v.Perf) {
			if p.FloatValue != nil {
				qV1.Lines[i].Perf[p.Alias] = *p.FloatValue
			} else {
				qV1.Lines[i].Perf[p.Alias] = *p.IntValue
			}
		}
	}
	return qV1
}



func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "check_nsc_web v"+AppVersion)
		fmt.Fprintf(os.Stderr, usage)
		flag.PrintDefaults()
	}

	var flagURL string
	var flagLogin string
	var flagPassword string
	var flagAPIVersion string
	var flagTimeout int
	var flagVerbose bool
	var flagJSON bool
	var flagVersion bool
	var flagInsecure bool
	var flagFloatround int
	var flagExtratext string

	flag.StringVar(&flagURL, "u", "", "NSCLient++ URL, for example https://10.1.2.3:8443.")
	flag.StringVar(&flagLogin, "l", "admin", "NSClient++ webserver login.")
	flag.StringVar(&flagPassword, "p", "", "NSClient++ webserver password.")
	flag.StringVar(&flagAPIVersion, "a", "legacy", "API version of NSClient++ (legacy or 1).")
	flag.IntVar(&flagTimeout, "t", 10, "Connection timeout in seconds.")
	flag.BoolVar(&flagVerbose, "v", false, "Enable verbose output.")
	flag.BoolVar(&flagJSON, "j", false, "Print out JSON response body.")
	flag.BoolVar(&flagVersion, "V", false, "Print program version.")
	flag.BoolVar(&flagInsecure, "k", false, "Insecure mode - skip TLS verification.")
	flag.IntVar(&flagFloatround, "f", -1, "Round performance data float values to this number of digits.")
	flag.StringVar(&flagExtratext, "x", "", "Extra text to appear in output.")

	ReturncodeMap := map[string]int{
		"OK":       0,
		"WARNING":  1,
		"CRITICAL": 2,
		"UNKNOWN":  3,
	}

	flag.Parse()
	if flagVersion {
		fmt.Fprintln(os.Stderr, "check_nsc_web v"+AppVersion)
		os.Exit(0)
	}
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})
	for _, req := range []string{"u", "p"} {
		if !seen[req] {
			fmt.Fprintf(os.Stderr, "UNKNOWN: Missing required -%s argument\n", req)
			fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
			flag.Usage()
			os.Exit(3)
		}
	}

	timeout := time.Second * time.Duration(flagTimeout)

	urlStruct, err := url.Parse(flagURL)
	if err != nil {
		fmt.Println("UNKNOWN: " + err.Error())
		os.Exit(3)
	}

	if len(flag.Args()) == 0 {
		urlStruct.Path += "/"
	} else {
		if flagAPIVersion == "1" {
			urlStruct.Path += "/api/v1/queries/" + flag.Arg(0) + "/commands/execute"
		} else {
			urlStruct.Path += "/query/" + flag.Arg(0)
		}
		if len(flag.Args()) > 1 {
			var param bytes.Buffer
			for i, a := range flag.Args() {
				if i == 0 {
					continue
				} else if i > 1 {
					param.WriteString("&")
				}

				p := strings.SplitN(a, "=", 2)
				if len(p) == 1 {
					param.WriteString(url.QueryEscape(p[0]))
				} else {
					param.WriteString(url.QueryEscape(p[0]) + "=" + url.QueryEscape(p[1]))
				}
				if err != nil {
					fmt.Println("UNKNOWN: " + err.Error())
					os.Exit(3)
				}
			}
			urlStruct.RawQuery = param.String()
		}
	}

	var hTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: flagInsecure,
		},
		Dial: (&net.Dialer{
			Timeout: timeout,
		}).Dial,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
	}
	var hClient = &http.Client{
		Timeout:   timeout,
		Transport: hTransport,
	}

	req, err := http.NewRequest("GET", urlStruct.String(), nil)
	if err != nil {
		fmt.Println("UNKNOWN: " + err.Error())
		os.Exit(3)
	}
	if flagAPIVersion == "1" && flagLogin != "" {
		req.Header.Add("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(flagLogin + ":" + flagPassword)))
	} else {
		req.Header.Add("password", flagPassword)
	}

	if flagVerbose {
		dumpreq, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Printf("REQUEST-ERROR:\n%s\n", err.Error())
		}
		fmt.Printf("REQUEST:\n%q\n", dumpreq)
	}
	res, err := hClient.Do(req)
	if err != nil {
		fmt.Println("UNKNOWN: " + err.Error())
		os.Exit(3)
	}
	defer res.Body.Close()

	if flagVerbose {
		dumpres, err := httputil.DumpResponse(res, true)
		if err != nil {
			fmt.Printf("RESPONSE-ERROR:\n%s\n", err.Error())
		}
		fmt.Printf("RESPONSE:\n%q\n", dumpres)
	}

	if len(flag.Args()) == 0 {
		fmt.Println("OK: NSClient API reachable on " + flagURL)
		os.Exit(0)
	} else {
		queryResult := new(QueryV1)
		if flagAPIVersion == "1" {
			json.NewDecoder(res.Body).Decode(queryResult)
		} else {
			queryLeg := new(QueryLeg)
			json.NewDecoder(res.Body).Decode(queryLeg)
			if len(queryLeg.Payload) == 0 {
				if flagVerbose {
					fmt.Printf("QUERY RESULT:\n%+v\n", queryLeg)
				}
				fmt.Println("UNKNOWN: The resultpayload size is 0")
				os.Exit(3)
			}
			queryResult = queryLeg.toV1()
		}


		if flagJSON {
			jsonStr, _ := json.Marshal(queryResult)
			fmt.Println(string(jsonStr))
			os.Exit(0)
		}

		var nagiosMessage string
		var nagiosPerfdata bytes.Buffer

		// FIXME how to iterate the slice of lines safely ?
		for _, l := range queryResult.Lines {

			nagiosMessage = strings.TrimSpace(l.Message)

			val := ""
			uni := ""
			war := ""
			cri := ""
			min := ""
			max := ""
			for m, p := range l.Perf {
				// FIXME what if crit is set but not warn - there need to be unfilled semicolons
				// REFERENCE 'label'=value[UOM];[warn];[crit];[min];[max]
				if p.Value != nil {
					val = strconv.FormatFloat(*(p.Value), 'f', flagFloatround, 64)
				} else {
					continue
				}
				if p.Unit != nil {
					uni = (*(p.Unit))
				}
				if p.Warning != nil {
					war = strconv.FormatFloat(*(p.Warning), 'f', flagFloatround, 64)
				}
				if p.Critical != nil {
					cri = strconv.FormatFloat(*(p.Critical), 'f', flagFloatround, 64)
				}
				if p.Minimum != nil {
					min = strconv.FormatFloat(*(p.Minimum), 'f', flagFloatround, 64)
				}
				if p.Maximum != nil {
					max = strconv.FormatFloat(*(p.Maximum), 'f', flagFloatround, 64)
				}
				nagiosPerfdata.WriteString(" '" + m + "'=" + val + uni + ";" + war + ";" + cri + ";" + min + ";" + max)
			}
		}

		if nagiosPerfdata.Len() == 0 {
			fmt.Println(nagiosMessage)
		} else {
			fmt.Println(nagiosMessage + "|" + strings.TrimSpace(nagiosPerfdata.String()))
		}
		os.Exit(ReturncodeMap[queryResult.Result])
	}

}
