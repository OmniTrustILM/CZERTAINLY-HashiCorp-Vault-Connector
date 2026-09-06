package authority

import (
	"context"
	"net/http"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"go.uber.org/zap"
)

func TestNewConnectorAttributesAPIService_WiresRepositoryAndLogger(t *testing.T) {
	repo, err := db.NewAuthorityRepository(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger := zap.NewNop()

	servicer := NewConnectorAttributesAPIService(repo, logger)

	service, ok := servicer.(*ConnectorAttributesAPIService)
	if !ok {
		t.Fatalf("type = %T, want *ConnectorAttributesAPIService", servicer)
	}
	if service.authorityRepo != authorityRepository(repo) {
		t.Error("authorityRepo not wired to the repository passed in")
	}
	if service.log != logger {
		t.Error("log not wired to the logger passed in")
	}
}

func TestListAttributeDefinitionsService(t *testing.T) {
	service := &ConnectorAttributesAPIService{log: zap.NewNop()}

	t.Run("recognized kind returns the attribute definitions", func(t *testing.T) {
		resp, err := service.ListAttributeDefinitions(context.Background(), model.CONNECTOR_KIND)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
		attributes, ok := resp.Body.([]model.Attribute)
		if !ok {
			t.Fatalf("body type = %T, want []model.Attribute", resp.Body)
		}
		if len(attributes) == 0 {
			t.Error("expected at least one attribute definition")
		}
	})

	t.Run("kind matching is case-insensitive", func(t *testing.T) {
		resp, err := service.ListAttributeDefinitions(context.Background(), "hvault")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
	})

	t.Run("unrecognized kind is rejected", func(t *testing.T) {
		resp, err := service.ListAttributeDefinitions(context.Background(), "some-other-connector")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnprocessableEntity)
		}
		messages, ok := resp.Body.([]string)
		if !ok || len(messages) != 1 {
			t.Fatalf("body = %+v (%T), want a single-element []string", resp.Body, resp.Body)
		}
	})
}

func TestCredentialAttributesCallbackService(t *testing.T) {
	service := &ConnectorAttributesAPIService{log: zap.NewNop()}

	tests := []struct {
		credentialType string
		wantUUIDs      []string
	}{
		{credentialType: model.APPROLE_CRED, wantUUIDs: []string{model.AUTHORITY_ROLE_ID_ATTR, model.AUTHORITY_ROLE_SECRET_ATTR, model.AUTHORITY_MOUNT_PATH_ATTR}},
		{credentialType: model.KUBERNETES_CRED, wantUUIDs: []string{model.AUTHORITY_VAULT_ROLE_ATTR, model.AUTHORITY_MOUNT_PATH_ATTR}},
		{credentialType: model.JWTOIDC_CRED, wantUUIDs: []string{model.AUTHORITY_VAULT_ROLE_ATTR, model.AUTHORITY_MOUNT_PATH_ATTR}},
		{credentialType: "unknown", wantUUIDs: []string{model.AUTHORITY_MOUNT_PATH_ATTR}},
	}

	for _, test := range tests {
		t.Run(test.credentialType, func(t *testing.T) {
			resp, err := service.CredentialAttributesCallback(context.Background(), test.credentialType)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
			}
			attributes, ok := resp.Body.([]model.Attribute)
			if !ok {
				t.Fatalf("body type = %T, want []model.Attribute", resp.Body)
			}
			if len(attributes) != len(test.wantUUIDs) {
				t.Fatalf("attributes = %+v, want %d entries", attributes, len(test.wantUUIDs))
			}
			for i, wantUUID := range test.wantUUIDs {
				if attributes[i].GetUuid() != wantUUID {
					t.Errorf("attributes[%d].Uuid = %q, want %q", i, attributes[i].GetUuid(), wantUUID)
				}
			}
		})
	}
}

func TestValidateAttributesService(t *testing.T) {
	service := &ConnectorAttributesAPIService{log: zap.NewNop()}

	t.Run("recognized kind is accepted", func(t *testing.T) {
		resp, err := service.ValidateAttributes(context.Background(), model.CONNECTOR_KIND, nil)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
		}
	})

	t.Run("unrecognized kind is rejected", func(t *testing.T) {
		resp, err := service.ValidateAttributes(context.Background(), "some-other-connector", nil)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnprocessableEntity)
		}
	})
}
