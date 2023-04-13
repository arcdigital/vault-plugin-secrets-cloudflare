package main

import (
	"os"

	cloudflareEngine "github.com/arcdigital/vault-plugin-secrets-cloudflare"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	_ = flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)
	logger := hclog.New(&hclog.LoggerOptions{})

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: cloudflareEngine.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger.Error("cloudflare plugin shutting down", "error", err)
		os.Exit(1)
	}
}
