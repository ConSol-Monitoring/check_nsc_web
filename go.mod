module github.com/consol-monitoring/check_nsc_web

go 1.21

replace pkg/checknscweb => ./pkg/checknscweb

require pkg/checknscweb v0.0.0-00010101000000-000000000000

require github.com/namsral/flag v1.7.4-pre // indirect
