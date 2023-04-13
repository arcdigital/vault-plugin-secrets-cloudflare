package cloudflare_secrets_engine

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type cloudflareBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *cloudflareClient
}

func backend() *cloudflareBackend {
	var b = cloudflareBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"service-token/*",
				//"api-token/*",
			},
		},
		Paths: framework.PathAppend(
			//pathApiTokens(&b),
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathServiceTokens(&b),
				//pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.cloudflareServiceToken(),
			//b.cloudflareApiToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func (b *cloudflareBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *cloudflareBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *cloudflareBackend) getClient(ctx context.Context, s logical.Storage) (*cloudflareClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(cloudflareConfig)
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

const backendHelp = `
The Cloudflare secrets backend dynamically generates Cloudflare API tokens and Access service tokens.
`
