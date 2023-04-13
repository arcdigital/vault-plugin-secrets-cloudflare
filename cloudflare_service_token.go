package cloudflare_secrets_engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	cloudflareServiceTokenType = "cloudflare_service_token"
)

type cloudflareServiceToken struct {
	TokenID      string `json:"token_id"`
	TokenName    string `json:"token_name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (token *cloudflareServiceToken) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"token_id":      token.TokenID,
		"token_name":    token.TokenName,
		"client_id":     token.ClientID,
		"client_secret": token.ClientSecret,
	}
	return respData
}

func (b *cloudflareBackend) cloudflareServiceToken() *framework.Secret {
	return &framework.Secret{
		Type: cloudflareServiceTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare Access Service Token ID",
			},
			"token_name": {
				Type:        framework.TypeString,
				Description: "Cloudflare Access Service Token Name",
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare Access Service Token Client ID",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "Cloudflare Access Service Token Client Secret",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func (b *cloudflareBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	tokenIdRaw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token_id internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	tokenId, ok := tokenIdRaw.(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	if err := deleteToken(ctx, client, tokenId, roleEntry); err != nil {
		return nil, fmt.Errorf("error revoking service token: %w", err)
	}
	return nil, nil
}

func (b *cloudflareBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	tokenIdRaw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token_id internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	tokenId := tokenIdRaw.(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	if err := renewToken(ctx, client, tokenId, roleEntry); err != nil {
		return nil, fmt.Errorf("error renewing service token: %w", err)
	}

	resp := &logical.Response{Secret: req.Secret}

	return resp, nil
}

func createToken(ctx context.Context, c *cloudflareClient, role *cloudflareRoleEntry) (*cloudflareServiceToken, error) {

	suffix := uuid.New().String()
	response, err := c.CreateAccessServiceToken(ctx, role.AccountID, "vault-account-"+suffix)
	if err != nil {
		return nil, fmt.Errorf("error creating account service token: %w", err)
	}
	return &cloudflareServiceToken{
		TokenID:      response.ID,
		TokenName:    response.Name,
		ClientID:     response.ClientID,
		ClientSecret: response.ClientSecret,
	}, nil
}

func renewToken(ctx context.Context, c *cloudflareClient, tokenId string, role *cloudflareRoleEntry) error {
	resourceContainer := cloudflare.AccountIdentifier(role.AccountID)
	_, err := c.RefreshAccessServiceToken(ctx, resourceContainer, tokenId)

	if err != nil {
		return err
	}

	return nil
}

func deleteToken(ctx context.Context, c *cloudflareClient, tokenId string, role *cloudflareRoleEntry) error {
	_, err := c.DeleteAccessServiceToken(ctx, role.AccountID, tokenId)
	if err != nil {
		return err
	}

	return nil
}
