package cloudflare_secrets_engine

import (
	"errors"
	"github.com/cloudflare/cloudflare-go"
)

type cloudflareClient struct {
	*cloudflare.API
}

func newClient(config *cloudflareConfig) (*cloudflareClient, error) {
	if config == nil {
		return nil, errors.New("cloudflare client configuration was nil")
	}

	if config.APIToken == "" {
		return nil, errors.New("cloudlfare API token was not defined")
	}

	c, err := cloudflare.NewWithAPIToken(config.APIToken)

	if err != nil {
		return nil, err
	}
	return &cloudflareClient{c}, nil
}
