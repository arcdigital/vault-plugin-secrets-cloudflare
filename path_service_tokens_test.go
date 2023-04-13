package cloudflare_secrets_engine

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		APIToken:  os.Getenv(envVarCloudflareApiToken),
		AccountID: os.Getenv(envVarCloudflareAccountId),
		Backend:   b,
		Context:   ctx,
		Storage:   &logical.InmemStorage{},
	}, nil
}

func TestAcceptanceServiceToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add service token role", acceptanceTestEnv.AddServiceTokenRole)
	t.Run("read service token cred", acceptanceTestEnv.ReadServiceToken)
	t.Run("read service token cred", acceptanceTestEnv.ReadServiceToken)
	t.Run("cleanup user tokens", acceptanceTestEnv.CleanupServiceTokens)
}
