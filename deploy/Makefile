.PHONY: ssh
ssh:
	ssh tortoise

.PHONY: scp
scp:
	(cd .. && go1.16rc1 build)
	scp ../f28491 ../conf.toml.production tortoise:~/run/f28491/
