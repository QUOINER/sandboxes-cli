BIN ?= bin/lsbx
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: build dev-bundle test check fmt lint vuln clean

build:
	go build -ldflags "-X github.com/lickren/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o $(BIN) ./cmd/lsbx

# Local workspace bundle; releases must use tagged module dependencies.
dev-bundle:
	go build -ldflags "-X github.com/lickren/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o dist/lsbx ./cmd/lsbx
	cd ../sandboxes-daemon && go build -o ../sandboxes-cli/dist/sandboxesd ./cmd/sandboxesd

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint config verify
	golangci-lint run ./...

vuln:
	govulncheck ./...

clean:
	rm -rf bin
