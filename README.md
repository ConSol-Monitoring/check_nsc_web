# About *check_nsc_web*

*check_nsc_web* collects check results from NSClient++/SNClient+ agents using its REST API. It is an alternative to check_nrpe et al.
*check_nsc_web* can be used with any monitoring tool, that can use Naemon/Nagios compatible plugins.

To be easily portable, *check_nsc_web* is written in Go.

*check_nsc_web* is released under the GNU GPL v3.

## Building the binaries

### With docker

```
make docker
```
or to select a specific makefile target
```
make docker target=citest
```

## Usage examples
* Alive check
```
go run ./cmd/check_nsc_web/main.go.go -k -p "password from nsclient.ini" -u "https://<SERVER_RUNNING_NSCLIENT>:8443"
OK: NSClient API reachable on https://localhost:8443
```

* CPU usage
```
check_nsc_web -k -p "password from nsclient.ini" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu
OK: CPU load is ok.|'total 5m'=16%;80;90 'total 1m'=8%;80;90 'total 5s'=8%;80;90
```
* CPU usage with thresholds
```
check_nsc_web -k -p "password from nsclient.ini" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu show-all "warning=load > 75" "critical=load > 90"
OK: 5m: 1%, 1m: 0%, 5s: 0%|'total 5m'=1%;75;90 'total 1m'=0%;75;90 'total 5s'=0%;75;90
```

* Service status
```
check_nsc_web -k -p "password from nsclient.ini" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_service "service=BvSshServer"
OK: All 1 service(s) are ok.|'BvSshServer'=4;0;0
```

* Complex eventlog check
```
check_nsc_web -k -p "password from nsclient.ini" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_eventlog "file=system" "filter=id=8000" "crit=count>0" "detail-syntax=\${message}" show-all "scan-range=-900m"
OK: No entries found|'count'=0;0;0 'problem_count'=0;0;0
```

* Reading parameters and queries from file
```
check_nsc_web -config ./sample.conf
OK: 5m: 0%, 1m: 0%, 5s: 0% |'total 5m'=0%;80;90;; 'total 1m'=0%;80;90;; 'total 5s'=0%;80;90;;
```

Contents of ```sample.conf```:
```
u https://127.0.0.1:28443
p password
k true
query check_cpu show-all
```

Please note, that everything after query will be *appended* to existing query arguments.

## Program help
```
Usage of ./check_nsc_web:

  check_nsc_web is a REST client for the NSClient++/SNClient+ webserver for querying
  and receiving check information over HTTPS.

  Example:
  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_cpu

  check_nsc_web -p "password" -u "https://<SERVER_RUNNING_NSCLIENT>:8443" check_drivesize disk=c

  Usage:
  check_nsc_web [options] [query parameters]

  check_nsc_web can and should be built with CGO_ENABLED=0

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
    -query <string>          Placeholder for query string from config file
```