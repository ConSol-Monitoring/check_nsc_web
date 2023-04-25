build:
	CGO_ENABLED=0 go build -ldflags -s

clean:
	rm -f check_nsc_web
