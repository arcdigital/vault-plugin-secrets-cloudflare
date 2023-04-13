package cloudflare_secrets_engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

type cloudflareConfig struct {
	//AccountID string `json:"account_id"`
	APIToken string `json:"api_token"`
}

func pathConfig(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			//"account_id": {
			//	Type:        framework.TypeString,
			//	Description: "Cloudflare Account ID",
			//	Required:    true,
			//	DisplayAttrs: &framework.DisplayAttributes{
			//		Name:      "Account ID",
			//		Sensitive: false,
			//	},
			//},
			"api_token": {
				Type:        framework.TypeString,
				Description: "Cloudflare API Token",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token",
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *cloudflareBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *cloudflareBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	apiToken := config.APIToken
	lastFour := apiToken[len(config.APIToken)-4:]

	mask := strings.Repeat("x", len(apiToken)-4)

	return &logical.Response{
		Data: map[string]interface{}{
			"api_token": mask + lastFour,
			//"account_id": config.AccountID,
		},
	}, nil
}

func (b *cloudflareBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(cloudflareConfig)
	}

	//if accountId, ok := data.GetOk("account_id"); ok {
	//	config.AccountID = accountId.(string)
	//} else if !ok && createOperation {
	//	return nil, fmt.Errorf("missing account_id in configuration")
	//}

	if apiToken, ok := data.GetOk("api_token"); ok {
		config.APIToken = apiToken.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing api_token in configuration")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *cloudflareBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*cloudflareConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(cloudflareConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSynopsis = `Configure the Cloudflare backend.`

const pathConfigHelpDescription = `
The Cloudflare secret backend requires credentials for managing tokens.
`
