.PHONY: ssh
ssh:
	ssh tortoise

.PHONY: scp
scp:
	(cd .. && go1.16rc1 build -o deploy/f28491)
	scp f28491 tortoise:~/run/f28491/
