package cloudflare_secrets_engine

import (
	"fmt"
	"os"
	"sync"
	"testing"

	stepwise "github.com/hashicorp/vault-testing-stepwise"
	dockerEnvironment "github.com/hashicorp/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestAccServiceToken(t *testing.T) {
	t.Parallel()
	if !runAcceptanceTests {
		t.SkipNow()
	}
	envOptions := &stepwise.MountOptions{
		RegistryName:    "test-cloudflare",
		PluginType:      stepwise.PluginTypeSecrets,
		PluginName:      "vault-plugin-secrets-cloudflare",
		MountPathPrefix: "cloudflare",
	}

	roleName := "vault-cloudflare-service-role"

	serviceToken := new(string)
	stepwise.Run(t, stepwise.Case{
		Precheck:    func() { testAccPreCheck(t) },
		Environment: dockerEnvironment.NewEnvironment("cloudflare", envOptions),
		Steps: []stepwise.Step{
			testAccConfig(t),
			testAccServiceRole(t, roleName),
			testAccServiceRoleRead(t, roleName),
			testAccServiceTokenRead(t, roleName, serviceToken),
		},
	})
}

var initSetup sync.Once

func testAccPreCheck(t *testing.T) {
	initSetup.Do(func() {
		if v := os.Getenv(envVarCloudflareAccountId); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarCloudflareAccountId))
		}
		if v := os.Getenv(envVarCloudflareApiToken); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarCloudflareApiToken))
		}
	})
}

func testAccConfig(t *testing.T) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"api_token": os.Getenv(envVarCloudflareApiToken),
		},
	}
}

func testAccServiceRole(t *testing.T, roleName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "role/" + roleName,
		Data: map[string]interface{}{
			"credential_type": "service",
			"account_id":      os.Getenv(envVarCloudflareAccountId),
		},
		Assert: func(resp *api.Secret, err error) error {
			require.Nil(t, resp)
			require.Nil(t, err)
			return nil
		},
	}
}

func testAccServiceRoleRead(t *testing.T, roleName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "role/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			return nil
		},
	}
}

func testAccServiceTokenRead(t *testing.T, roleName string, serviceToken *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "service-token/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Data["client_secret"])
			*serviceToken = resp.Data["client_secret"].(string)
			return nil
		},
	}
}
