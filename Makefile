test:
	go vet ./...
	go test -v ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f coverage.html coverage.out

.DEFAULT_GOAL := test
