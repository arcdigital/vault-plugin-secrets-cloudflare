package cloudflare_secrets_engine

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type cloudflareRoleEntry struct {
	CredentialType string `json:"type"`
	AccountID      string `json:"account_id"`
	//ZoneID         string        `json:"zone_id"`
	//TTL    time.Duration `json:"ttl"`
	//MaxTTL time.Duration `json:"max_ttl"`
}

//func (r *cloudflareRoleEntry) toResponseData() map[string]interface{} {
//	respData := map[string]interface{}{
//		"credential_type":     r.TTL.Seconds(),
//		"account_id":     r.TTL.Seconds(),
//		"zone_id":     r.TTL.Seconds(),
//		"ttl":     r.TTL.Seconds(),
//		"max_ttl": r.MaxTTL.Seconds(),
//	}
//	return respData
//}

func pathRole(b *cloudflareBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"credential_type": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("The credential type, either \"service\" for Access or \"api\" for API"),
					Required:    true,
				},
				"account_id": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("The cloudflare account id to generate credentials for"),
					Required:    true,
				},
				//"zone_id": {
				//	Type:        framework.TypeString,
				//	Description: fmt.Sprintf("The zone id to scope the service token to"),
				//},
				//"ttl": {
				//	Type:        framework.TypeDurationSecond,
				//	Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				//},
				//"max_ttl": {
				//	Type:        framework.TypeDurationSecond,
				//	Description: "Maximum time for role. If not set or set to 0, will use system default.",
				//},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
			ExistenceCheck:  b.pathRoleExistenceCheck,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *cloudflareBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *cloudflareBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var data = make(map[string]interface{})
	data["credential_type"] = entry.CredentialType
	//data["ttl"] = entry.TTL / time.Second
	//data["max_ttl"] = entry.MaxTTL / time.Second
	if entry.CredentialType == "service" {
		data["account_id"] = entry.AccountID
		//data["zone_id"] = entry.ZoneID
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *cloudflareBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing cloudflare role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &cloudflareRoleEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if credentialType, ok := d.GetOk("credential_type"); ok {
		if credentialType == "service" {
			roleEntry.CredentialType = credentialType.(string)
		} else {
			return nil, fmt.Errorf("invalid credential_type in cloudflare role")
		}
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing credential_type in cloudflare role")
	}

	if accountId, ok := d.GetOk("account_id"); ok {
		roleEntry.AccountID = accountId.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing account_id in cloudflare role")
	}

	//if zoneId, ok := d.GetOk("zone_id"); ok {
	//	roleEntry.ZoneID = zoneId.(string)
	//}

	//if ttlRaw, ok := d.GetOk("ttl"); ok {
	//	roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	//} else if createOperation {
	//	roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	//}
	//
	//if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
	//	roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	//} else if createOperation {
	//	roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	//}
	//
	//if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
	//	return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	//}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *cloudflareBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting cloudflare role: %w", err)
	}

	return nil, nil
}

func (b *cloudflareBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))

	if err != nil {
		return false, fmt.Errorf("error reading cloudflare role: %w", err)
	}

	return entry != nil, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *cloudflareRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for cloudflare role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *cloudflareBackend) getRole(ctx context.Context, s logical.Storage, name string) (*cloudflareRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role cloudflareRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault roles for generating cloudflare tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate cloudflare tokens.
`

	pathRoleListHelpSynopsis    = `List the existing roles in the cloudflare backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
