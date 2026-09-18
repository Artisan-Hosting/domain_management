BINARY     := nginx-r2-agent
CMD        := ./cmd/agent
DIST       := dist
GOFLAGS    ?=
LDFLAGS    := -s -w

.PHONY: all build tidy fmt vet check clean install \
        linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 cross

all: build

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

tidy:
	go mod tidy

fmt:
	gofmt -l .

vet:
	go vet ./...

check: fmt vet
	go build $(GOFLAGS) -o /dev/null $(CMD)

clean:
	rm -rf $(BINARY) $(DIST)

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

linux-amd64:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)

linux-arm64:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)

darwin-amd64:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-darwin-amd64 $(CMD)

darwin-arm64:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-darwin-arm64 $(CMD)

cross: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64
