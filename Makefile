.PHONY: all
all: build serve

.PHONY: build
build:
	go1.16rc1 build

.PHONY: serve
serve:
	./f28491 conf.toml.dev

.PHONY: vet
vet:
	go1.16rc1 vet ./...

.PHONY: scp
scp: build
	scp f28491 conf.toml.production tortoise:~/run/f28491/
