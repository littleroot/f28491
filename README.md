## passweb

A web user interface for [pass][1]. The web interface is served by a Go
server.

## Install

Requires Go version 1.16 or higher to build.

```
go install github.com/littleroot/passweb@latest
```

## Usage

```
usage: passweb <conf.toml>
```

See `conf.toml.example` for an example config.

GPG keys should be in the default GPG homedir `~/.gnupg`. SSH keys for git
operations should be in the location specified in the `conf.toml`.

## Runtime requirements

```
- pass
- git
- ssh
- gpg
```

[1]: http://passworstore.org
