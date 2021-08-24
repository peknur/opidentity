run-example:
	cd example/httpd && go run main.go
tests:
	go test
	go test opidentity/jwk