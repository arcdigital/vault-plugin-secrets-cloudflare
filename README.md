# vault-plugin-secrets-cloudflare
Vault Secrets Plugin for Cloudflare Tokens

## Install

1. Run `go mod init`.

1. Build the secrets engine.
   ```shell
   $ go build -o bin/vault-plugin-secrets-cloudflare cmd/vault-plugin-secrets-cloudflare/main.go
   ```

1. You can find the binary in `bin/`.
   ```shell
   $ ls bin/
   ```

1. Run a Vault server in `dev` mode to register and try out the plugin.
   ```shell
   $ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin
   ```