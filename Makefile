.PHONY: test
test:
	go test -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run
