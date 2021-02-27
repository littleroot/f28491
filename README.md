# passweb

A server and a web user interface for [pass][1]. Requires Go version 1.16 or higher.

## Usage

```
usage: passweb <conf.toml>
```

See `conf.toml.example` for an example config.

## Runtime requirements

- git
- pass
- ssh
- gpg

GPG keys should be in the default GPG homedir `~/.gnupg`. SSH keys for git
operations should be in the location specified in the `conf.toml`.

[1]: http://passworstore.org
