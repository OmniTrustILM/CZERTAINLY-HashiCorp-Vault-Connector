package authority

import (
	"context"
	"fmt"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/vault"
	"os"
	"strings"

	"net/http"

	"go.uber.org/zap"
)

// ConnectorAttributesAPIService is a service that implements the logic for the ConnectorAttributesAPIServicer
// This service should implement the business logic for every endpoint for the ConnectorAttributesAPI API.
// Include any external packages or services that will be required by this service.
type ConnectorAttributesAPIService struct {
	authorityRepo authorityRepository
	log           *zap.Logger
}

// NewConnectorAttributesAPIService creates a default api service
func NewConnectorAttributesAPIService(authorityRepo *db.AuthorityRepository, logger *zap.Logger) ConnectorAttributesAPIServicer {
	return &ConnectorAttributesAPIService{
		authorityRepo: authorityRepo,
		log:           logger,
	}
}

// ListAttributeDefinitions - List available Attributes
func (s *ConnectorAttributesAPIService) ListAttributeDefinitions(ctx context.Context, kind string) (model.ImplResponse, error) {
	if !strings.EqualFold(kind, model.CONNECTOR_KIND) {
		message := fmt.Sprintf("Unrecognized Authority Instance kind: %s", kind)
		return model.Response(http.StatusUnprocessableEntity, []string{message}), nil
	}

	attributes := make([]model.Attribute, 0)
	attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_INFO_ATTR))
	attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_URL_ATTR))
	attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_GROUP_CREDENTIAL_TYPE_ATTR))
	credentialTypeAttribute := model.GetAttributeDefByUUID(model.AUTHORITY_CREDENTIAL_TYPE_ATTR).(model.DataAttribute)
	credentialTypes := []model.AttributeContent{
		model.GetCredentialTypeByName(model.APPROLE_CRED),
		model.GetCredentialTypeByName(model.JWTOIDC_CRED),
	}
	_, err := os.OpenFile(vault.DEFAULT_K8S_TOKEN_PATH, os.O_RDONLY, 0644)
	if !os.IsNotExist(err) {
		credentialTypes = append(credentialTypes, model.GetCredentialTypeByName(model.KUBERNETES_CRED))
	}

	credentialTypeAttribute.Content = credentialTypes
	attributes = append(attributes, credentialTypeAttribute)

	return model.Response(http.StatusOK, attributes), nil
}

func (s *ConnectorAttributesAPIService) CredentialAttributesCallback(ctx context.Context, credentialType string) (model.ImplResponse, error) {
	attributes := make([]model.Attribute, 0)
	switch credentialType {
	case model.APPROLE_CRED:
		attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_ROLE_ID_ATTR))
		attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_ROLE_SECRET_ATTR))
	case model.KUBERNETES_CRED, model.JWTOIDC_CRED:
		attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_VAULT_ROLE_ATTR))
	}
	attributes = append(attributes, model.GetAttributeDefByUUID(model.AUTHORITY_MOUNT_PATH_ATTR))
	return model.Response(http.StatusOK, attributes), nil
}

// ValidateAttributes - Validate Attributes
func (s *ConnectorAttributesAPIService) ValidateAttributes(ctx context.Context, kind string, requestAttributeDto []model.Attribute) (model.ImplResponse, error) {
	if !strings.EqualFold(kind, model.CONNECTOR_KIND) {
		message := fmt.Sprintf("Unrecognized Authority Instance kind: %s", kind)
		return model.Response(http.StatusUnprocessableEntity, []string{message}), nil
	}

	return model.Response(http.StatusOK, nil), nil
}
