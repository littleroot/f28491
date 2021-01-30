.PHONY: all
all: build-wasm build

.PHONY: build
build:
	go1.16rc1 build

.PHONY: vet
vet:
	go1.16rc1 vet ./...

.PHONY: build-wasm
build-wasm:
	GOOS=js GOARCH=wasm go1.16rc1 build -o static/webui.wasm ./wasm/cmd/webui
