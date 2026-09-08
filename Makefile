.PHONY: test vet lint build helm-lint clean

GOFLAGS ?=
LDFLAGS ?= -s -w
MODULE  := github.com/jville-family/external-dns-firewalla

test:
	go test $(GOFLAGS) -race -cover ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/listener ./cmd/listener
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/proxy ./cmd/proxy

build-listener-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/listener-linux-arm64 ./cmd/listener

build-listener-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/listener-linux-amd64 ./cmd/listener

helm-lint:
	helm lint charts/external-dns-firewalla

clean:
	rm -rf bin/
