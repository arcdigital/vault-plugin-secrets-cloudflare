package cloudflare_secrets_engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathServiceTokens(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "service-token/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathServiceTokensRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathServiceTokensRead,
			},
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *cloudflareBackend) pathServiceTokensRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleName, roleEntry)
}

func (b *cloudflareBackend) createUserCreds(ctx context.Context, req *logical.Request, roleName string, role *cloudflareRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(cloudflareServiceTokenType).Response(token.toResponseData(), map[string]interface{}{
		"token_name":    token.TokenName,
		"token_id":      token.TokenID,
		"client_id":     token.ClientID,
		"client_secret": token.ClientSecret,
		"role":          roleName,
	})

	return resp, nil
}

func (b *cloudflareBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *cloudflareRoleEntry) (*cloudflareServiceToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *cloudflareServiceToken

	token, err = createToken(ctx, client, roleEntry)
	if err != nil {
		return nil, fmt.Errorf("error creating service token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating service token")
	}

	return token, nil
}

const pathCredentialsHelpSyn = `
Generate a Cloudflare service token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Cloudflare service token
based on a particular role.
`
