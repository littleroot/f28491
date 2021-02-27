.PHONY: all
all: build serve

.PHONY: build
build:
	go build

.PHONY: serve
serve:
	./passweb conf.toml.dev

.PHONY: vet
vet:
	go vet ./...
