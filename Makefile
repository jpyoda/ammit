VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint fixtures clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/ammit ./cmd/ammit
	if [ -d cmd/ammit-judge ]; then go build -trimpath -ldflags "-s -w" -o bin/ammit-judge ./cmd/ammit-judge; fi

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

fixtures: build
	./bin/ammit scan --fail-on none testdata/fixtures/*

clean:
	rm -rf bin
