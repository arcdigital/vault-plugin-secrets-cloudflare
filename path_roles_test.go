package cloudflare_secrets_engine

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	roleName  = "testServiceRole"
	accountId = "testaccountid"
)

func TestServiceRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testServiceRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"credential_type": "service",
					"account_id":      accountId,
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create Service Role", func(t *testing.T) {
		resp, err := testServiceRoleCreate(t, b, s, roleName, map[string]interface{}{
			"credential_type": "service",
			"account_id":      accountId,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Read Service Role", func(t *testing.T) {
		resp, err := testServiceRoleRead(t, b, s, roleName)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["account_id"], accountId)
	})

	t.Run("Update Service Role", func(t *testing.T) {
		resp, err := testServiceRoleUpdate(t, b, s, roleName, map[string]interface{}{
			"account_id": accountId + "-updated",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Reread Service Role", func(t *testing.T) {
		resp, err := testServiceRoleRead(t, b, s, roleName)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["account_id"], accountId+"-updated")
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testServiceRoleDelete(t, b, s, roleName)

		require.NoError(t, err)
	})
}

func testServiceRoleCreate(t *testing.T, b *cloudflareBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func testServiceRoleUpdate(t *testing.T, b *cloudflareBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

func testServiceRoleRead(t *testing.T, b *cloudflareBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + name,
		Storage:   s,
	})
}

func testTokenRoleList(t *testing.T, b *cloudflareBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
}

func testServiceRoleDelete(t *testing.T, b *cloudflareBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/" + name,
		Storage:   s,
	})
}
