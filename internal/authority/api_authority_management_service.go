package authority

import (
	"context"
	"encoding/json"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/vault"
	vault2 "github.com/hashicorp/vault-client-go"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// AuthorityManagementAPIService is a service that implements the logic for the AuthorityManagementAPIServicer
// This service should implement the business logic for every endpoint for the AuthorityManagementAPI API.
// Include any external packages or services that will be required by this service.
type AuthorityManagementAPIService struct {
	authorityRepo *db.AuthorityRepository
	log           *zap.Logger
}

// NewAuthorityManagementAPIService creates a default api service
func NewAuthorityManagementAPIService(authorityRepo *db.AuthorityRepository, logger *zap.Logger) AuthorityManagementAPIServicer {
	return &AuthorityManagementAPIService{
		authorityRepo: authorityRepo,
		log:           logger,
	}
}

// CreateAuthorityInstance - Create Authority instance
func (s *AuthorityManagementAPIService) CreateAuthorityInstance(ctx context.Context, request model.AuthorityProviderInstanceRequestDto) (model.ImplResponse, error) {
	attributes := request.Attributes
	URL := model.GetAttributeFromArrayByUUID(model.AUTHORITY_URL_ATTR, attributes).GetContent()[0].GetData().(string)
	credentialType := model.GetAttributeFromArrayByUUID(model.AUTHORITY_CREDENTIAL_TYPE_ATTR, attributes).GetContent()[0].GetData().(string)
	var roleId, secretId, mountPath, vaultRole string
	if model.GetAttributeFromArrayByUUID(model.AUTHORITY_MOUNT_PATH_ATTR, attributes) != nil {
		mountPath = model.GetAttributeFromArrayByUUID(model.AUTHORITY_MOUNT_PATH_ATTR, attributes).GetContent()[0].GetData().(string)
	}
	switch credentialType {
	case model.APPROLE_CRED:
		roleId = model.GetAttributeFromArrayByUUID(model.AUTHORITY_ROLE_ID_ATTR, attributes).GetContent()[0].(model.SecretAttributeContent).GetData().(model.SecretAttributeContentData).Secret
		secretId = model.GetAttributeFromArrayByUUID(model.AUTHORITY_ROLE_SECRET_ATTR, attributes).GetContent()[0].(model.SecretAttributeContent).GetData().(model.SecretAttributeContentData).Secret
	case model.KUBERNETES_CRED, model.JWTOIDC_CRED:
		if model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes) != nil {
			vaultRole = model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes).GetContent()[0].GetData().(string)
		}
	}
	authorityName := request.Name
	marshaledAttrs, err := json.Marshal(attributes)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to marshal attributes",
		}), err
	}
	authority := db.AuthorityInstance{
		UUID:           utils.DeterministicGUID(authorityName),
		Name:           authorityName,
		URL:            URL,
		RoleId:         roleId,
		RoleSecret:     secretId,
		Attributes:     string(marshaledAttrs),
		MountPath:      mountPath,
		VaultRole:      vaultRole,
		CredentialType: credentialType,
	}

	// Do not store the authority in the database before the connection is validated
	_, err = vault.GetClient(authority)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Failed to connect to vault",
		}), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Creating authority", zap.String("name", authority.Name),
		zap.String("uuid", authority.UUID), zap.String("url", authority.URL),
		zap.String("credentialType", authority.CredentialType),
		zap.String("mountPath", authority.MountPath), zap.String("vaultRole", authority.VaultRole))
	err = s.authorityRepo.CreateAuthorityInstance(&authority)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to create authority",
		}), err
	}
	dto := model.AuthorityProviderInstanceDto{
		Uuid:       authority.UUID,
		Name:       authority.Name,
		Attributes: attributes,
	}
	return model.Response(http.StatusOK, dto), nil
}

// GetAuthorityInstance - Get an Authority instance
func (s *AuthorityManagementAPIService) GetAuthorityInstance(ctx context.Context, uuid string) (model.ImplResponse, error) {
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{
			Message: "Authority not found",
		}), nil
	}
	attributes := model.UnmarshalAttributes([]byte(authority.Attributes))
	authorityDto := model.AuthorityProviderInstanceDto{
		Uuid:       authority.UUID,
		Name:       authority.Name,
		Attributes: attributes,
	}
	return model.Response(http.StatusOK, authorityDto), nil
}

// GetCaCertificates - Get the Authority Instance&#39;s certificate chain
func (s *AuthorityManagementAPIService) GetCaCertificates(ctx context.Context, uuid string, caCertificatesRequestDto model.CaCertificatesRequestDto) (model.ImplResponse, error) {
	engineName, err := getRAProfileEngineName(caCertificatesRequestDto.RaProfileAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		}), nil
	}
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{
			Message: "Authority not found",
		}), nil
	}

	client, err := vault.GetClient(*authority)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Getting CA certificates", zap.String("authority", authority.Name), zap.String("uuid", authority.UUID))
	//https://github.com/hashicorp/vault/issues/919 do not use PkiReadCaChainPem
	certificateCaResponse, err := client.Secrets.PkiReadCertCaChain(ctx, vault2.WithMountPath(engineName+"/"))

	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	var caChainCertificates []model.CertificateDataResponseDto
	chain, err := utils.GetCertificatesFromDer([]byte(certificateCaResponse.Data.CaChain))
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to parse certificate chain",
		}), err

	}
	for _, cert := range chain {
		caChainCertificates = append(caChainCertificates, model.CertificateDataResponseDto{
			CertificateData: cert,
			Uuid:            utils.DeterministicGUID(),
			Meta:            nil,
			CertificateType: "X.509",
		})
	}
	caCertificatesResponseDto := model.CaCertificatesResponseDto{
		Certificates: caChainCertificates,
	}

	return model.Response(http.StatusOK, caCertificatesResponseDto), nil
}

// GetConnection - Connect to Authority
func (s *AuthorityManagementAPIService) GetConnection(ctx context.Context, uuid string) (model.ImplResponse, error) {
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to marshal attributes",
		}), err
	}

	_, err = vault.GetClient(*authority)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Failed to connect to vault",
		}), nil
	}

	return model.Response(http.StatusOK, nil), nil
}

// GetCrl - Get the latest CRL for the Authority Instance
func (s *AuthorityManagementAPIService) GetCrl(ctx context.Context, uuid string, certificateRevocationListRequestDto model.CertificateRevocationListRequestDto) (model.ImplResponse, error) {
	engineName, err := getRAProfileEngineName(certificateRevocationListRequestDto.RaProfileAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		}), nil
	}
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{
			Message: "Authority not found",
		}), nil
	}

	client, err := vault.GetClient(*authority)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil
	}

	var chain []string
	if certificateRevocationListRequestDto.Delta {
		s.log.With(zax.Get(ctx)...).Info("Getting Delta CRL", zap.String("authority", authority.Name), zap.String("uuid", authority.UUID))
		deltaCrl, err := client.Secrets.PkiReadCertDeltaCrl(ctx, vault2.WithMountPath(engineName+"/"))
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to read Delta CRL",
			}), err
		}
		chain, err = utils.GetCertificatesFromDer([]byte(deltaCrl.Data.CaChain))
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to parse delta CRL records",
			}), err

		}

	} else {
		s.log.With(zax.Get(ctx)...).Info("Getting CRL", zap.String("authority", authority.Name), zap.String("uuid", authority.UUID))
		completeCrl, err := client.Secrets.PkiReadCertCrl(ctx, vault2.WithMountPath(engineName+"/"))
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to read CRL",
			}), err
		}
		chain, err = utils.GetCertificatesFromDer([]byte(completeCrl.Data.CaChain))
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to parse CRL records",
			}), err

		}
	}

	var caChainCertificates []model.CertificateDataResponseDto

	for _, cert := range chain {
		caChainCertificates = append(caChainCertificates, model.CertificateDataResponseDto{
			CertificateData: cert,
			Uuid:            utils.DeterministicGUID(),
			Meta:            nil,
			CertificateType: "X.509",
		})
	}
	caCertificatesResponseDto := model.CaCertificatesResponseDto{
		Certificates: caChainCertificates,
	}

	return model.Response(http.StatusOK, caCertificatesResponseDto), nil
}

// ListAuthorityInstances - List Authority instances
func (s *AuthorityManagementAPIService) ListAuthorityInstances(ctx context.Context) (model.ImplResponse, error) {
	authorities, _ := s.authorityRepo.ListAuthorityInstances()
	var authoritiesDto []model.AuthorityProviderInstanceDto
	for _, authority := range authorities {
		attributes := model.UnmarshalAttributes([]byte(authority.Attributes))
		authoritiesDto = append(authoritiesDto, model.AuthorityProviderInstanceDto{
			Uuid:       authority.UUID,
			Name:       authority.Name,
			Attributes: attributes,
		})
	}

	return model.Response(http.StatusOK, authoritiesDto), nil
}

// ListRAProfileAttributes - List RA Profile Attributes
func (s *AuthorityManagementAPIService) ListRAProfileAttributes(ctx context.Context, uuid string) (model.ImplResponse, error) {
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{
			Message: "Authority not found",
		}), nil
	}
	client, err := vault.GetClient(*authority)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to create vault client",
		}), err
	}
	//Due to the nature of its intended usage, there is no guarantee on backwards compatibility for this endpoint.
	mounts, _ := client.System.InternalUiListEnabledVisibleMounts(ctx)
	var engineList []model.AttributeContent
	for engineName, engineData := range mounts.Data.Secret {
		engineName = strings.TrimSuffix(engineName, "/")
		if engineData.(map[string]any)["type"] == "pki" {

			engineDataObject := make(map[string]any)
			engineDataObject["engineName"] = engineName
			engineDataObject["engineAccesor"] = engineData.(map[string]any)["accessor"]
			engineDataObject["runningPluginVersion"] = engineData.(map[string]any)["running_plugin_version"]

			engineList = append(engineList, model.ObjectAttributeContent{
				Reference: engineName,
				Data:      engineDataObject,
			})
		}
	}
	var resultAttributes []model.Attribute
	attribute := model.GetAttributeDefByUUID(model.RA_PROFILE_ENGINE_ATTR).(model.DataAttribute)
	attribute.Content = engineList
	resultAttributes = append(resultAttributes, attribute)
	attribute = model.GetAttributeDefByUUID(model.RA_PROFILE_AUTHORITY_ATTR).(model.DataAttribute)
	attribute.Content = []model.AttributeContent{
		model.StringAttributeContent{
			Reference: authority.Name,
			Data:      authority.UUID,
		},
	}
	resultAttributes = append(resultAttributes, attribute)
	resultAttributes = append(resultAttributes, model.GetAttributeDefByUUID(model.RA_PROFILE_ROLE_ATTR))
	return model.Response(http.StatusOK, resultAttributes), nil
}

// RemoveAuthorityInstance - Remove Authority instance
func (s *AuthorityManagementAPIService) RemoveAuthorityInstance(ctx context.Context, uuid string) (model.ImplResponse, error) {
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(204, nil), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Removing authority", zap.String("name", authority.Name), zap.String("uuid", authority.UUID))
	// Delete the authority if it has been found
	err = s.authorityRepo.DeleteAuthorityInstance(authority)
	if err != nil {
		// Handle error, failed to delete authority
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{}), err
	}

	// Return success response
	return model.Response(http.StatusOK, nil), nil

}

// UpdateAuthorityInstance - Update Authority instance
func (s *AuthorityManagementAPIService) UpdateAuthorityInstance(ctx context.Context, uuid string, request model.AuthorityProviderInstanceRequestDto) (model.ImplResponse, error) {
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to marshal attributes",
		}), err
	}
	attributes := request.Attributes
	URL := model.GetAttributeFromArrayByUUID(model.AUTHORITY_URL_ATTR, attributes).GetContent()[0].GetData().(string)
	credentialType := model.GetAttributeFromArrayByUUID(model.AUTHORITY_CREDENTIAL_TYPE_ATTR, attributes).GetContent()[0].GetData().(string)
	authorityName := request.Name
	var roleId, secretId, mountPath, vaultRole string
	if model.GetAttributeFromArrayByUUID(model.AUTHORITY_MOUNT_PATH_ATTR, attributes) != nil {
		mountPath = model.GetAttributeFromArrayByUUID(model.AUTHORITY_MOUNT_PATH_ATTR, attributes).GetContent()[0].GetData().(string)
	}
	if model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes) != nil {
		vaultRole = model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes).GetContent()[0].GetData().(string)
	}
	switch credentialType {
	case model.APPROLE_CRED:
		roleId = model.GetAttributeFromArrayByUUID(model.AUTHORITY_ROLE_ID_ATTR, attributes).GetContent()[0].(model.SecretAttributeContent).GetData().(model.SecretAttributeContentData).Secret
		secretId = model.GetAttributeFromArrayByUUID(model.AUTHORITY_ROLE_SECRET_ATTR, attributes).GetContent()[0].(model.SecretAttributeContent).GetData().(model.SecretAttributeContentData).Secret
	case model.KUBERNETES_CRED, model.JWTOIDC_CRED:
		if model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes) != nil {
			vaultRole = model.GetAttributeFromArrayByUUID(model.AUTHORITY_VAULT_ROLE_ATTR, attributes).GetContent()[0].GetData().(string)
		}

	}
	marshaledAttrs, err := json.Marshal(attributes)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to marshal attributes",
		}), err
	}
	authority.Name = authorityName
	authority.URL = URL
	authority.CredentialType = credentialType
	authority.RoleId = roleId
	authority.RoleSecret = secretId
	authority.MountPath = mountPath
	authority.VaultRole = vaultRole
	authority.Attributes = string(marshaledAttrs)

	s.log.With(zax.Get(ctx)...).Info("Updating authority", zap.String("name", authority.Name),
		zap.String("uuid", authority.UUID), zap.String("url", authority.URL),
		zap.String("credentialType", authority.CredentialType),
		zap.String("mountPath", authority.MountPath), zap.String("vaultRole", authority.VaultRole))
	err = s.authorityRepo.UpdateAuthorityInstance(authority)
	if err != nil {
		// Handle error, failed to delete authority
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{}), err
	}
	attributesEntity := model.UnmarshalAttributes([]byte(authority.Attributes))
	authorityDto := model.AuthorityProviderInstanceDto{
		Uuid:       authority.UUID,
		Name:       authority.Name,
		Attributes: attributesEntity,
	}
	return model.Response(http.StatusOK, authorityDto), nil

}

// ValidateRAProfileAttributes - Validate RA Profile attributes
func (s *AuthorityManagementAPIService) ValidateRAProfileAttributes(ctx context.Context, uuid string, requestAttributeDto []model.RequestAttributeDto) (model.ImplResponse, error) {
	s.log.With(zax.Get(ctx)...).Info("Validating RA Profile attributes", zap.String("uuid", uuid))
	return model.Response(http.StatusOK, nil), nil
}

func (s *AuthorityManagementAPIService) RAProfileCallback(ctx context.Context, uuid string, engineName string) (model.ImplResponse, error) {
	if !isValidVaultMountPath(engineName) {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		}), nil
	}
	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		//return model.Response(http.StatusNotFound, model.ErrorMessageDto{
		//	Message: "Authority not found by UUID"+ uuid,
		//}), nil
		//TODO: UI is sending back name instead of UUID, try to search also by name
		authority, err = s.authorityRepo.FindAuthorityInstanceByName(uuid)
		if err != nil {
			return model.Response(http.StatusNotFound, model.ErrorMessageDto{
				Message: "Authority not found by name" + uuid,
			}), nil
		}
	}
	client, err := vault.GetClient(*authority)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to create vault client",
		}), err
	}

	s.log.With(zax.Get(ctx)...).Info("Getting roles for callback", zap.String("authority", authority.Name), zap.String("uuid", authority.UUID))
	roles, err := client.Secrets.PkiListRoles(ctx, vault2.WithMountPath(engineName+"/"))
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Failed to list roles for engine " + engineName,
		}), nil
	}
	if roles == nil {
		return model.Response(http.StatusOK, []model.AttributeContent{}), nil
	}
	var roleList []model.AttributeContent
	for _, roleName := range roles.Data.Keys {

		roleList = append(roleList, model.StringAttributeContent{
			Reference: roleName,
			Data:      roleName,
		})

	}
	return model.Response(http.StatusOK, roleList), nil
}
