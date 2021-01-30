.PHONY: build
build:
	go1.16rc1 build

.PHONY: vet
vet:
	go1.16rc1 vet ./...
