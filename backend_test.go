package cloudflare_secrets_engine

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAcceptanceTests  = "VAULT_ACC"
	envVarCloudflareApiToken  = "TEST_CLOUDFLARE_API_TOKEN"
	envVarCloudflareAccountId = "TEST_CLOUDFLARE_ACCOUNT_ID"
)

func getTestBackend(tb testing.TB) (*cloudflareBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*cloudflareBackend), config.StorageView
}

var runAcceptanceTests = os.Getenv(envVarRunAcceptanceTests) == "1"

type testEnv struct {
	APIToken  string
	AccountID string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	SecretToken string

	Tokens []string
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"api_token": e.APIToken,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) AddServiceTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-service-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"credential_type": "service",
			"account_id":      e.AccountID,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadServiceToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "service-token/test-service-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["token_id"]; ok {
		e.Tokens = append(e.Tokens, t.(string))
	}
	require.NotEmpty(t, resp.Data["client_secret"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["client_secret"])
	}

	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["token_id"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) CleanupServiceTokens(t *testing.T) {
	if len(e.Tokens) != 2 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Tokens))
	}

	for _, token := range e.Tokens {
		b := e.Backend.(*cloudflareBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}
		if _, err := client.DeleteAccessServiceToken(e.Context, e.AccountID, token); err != nil {
			t.Fatalf("unexpected error deleting user token: %s - %s", token, err)
		}
	}
}
