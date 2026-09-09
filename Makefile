.PHONY: test vet lint build helm-lint clean build-listener-arm64 build-listener-amd64 deploy-listener

GOFLAGS ?=
LDFLAGS ?= -s -w
MODULE  := github.com/jville-family/external-dns-firewalla

# Override for Gold / Gold Pro (amd64) or a specific host, e.g.
#   make deploy-listener FIREWALLA_SSH=pi@192.168.1.1 FIREWALLA_ARCH=amd64
FIREWALLA_SSH  ?= pi@firewalla
FIREWALLA_ARCH ?= arm64
FIREWALLA_DIR  ?= /home/pi/.firewalla/k8s-external-dns
UNIT_NAME      := k8s-external-dns-listener.service

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

deploy-listener: build-listener-$(FIREWALLA_ARCH)
	scp bin/listener-linux-$(FIREWALLA_ARCH) $(FIREWALLA_SSH):/tmp/k8s-external-dns-listener
	scp deploy/firewalla/$(UNIT_NAME) $(FIREWALLA_SSH):/tmp/$(UNIT_NAME)
	ssh $(FIREWALLA_SSH) 'set -euo pipefail; \
		install -m 0755 /tmp/k8s-external-dns-listener $(FIREWALLA_DIR)/listener; \
		cp /tmp/$(UNIT_NAME) $(FIREWALLA_DIR)/$(UNIT_NAME); \
		sudo install -m 0644 $(FIREWALLA_DIR)/$(UNIT_NAME) /etc/systemd/system/$(UNIT_NAME); \
		sudo systemctl daemon-reload; \
		sudo systemctl restart $(UNIT_NAME)'

helm-lint:
	helm lint charts/external-dns-firewalla

clean:
	rm -rf bin/
