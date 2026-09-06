package authority

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/vault"
	vault2 "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"net/http"
)

// CertificateManagementAPIService is a service that implements the logic for the CertificateManagementAPIServicer
// This service should implement the business logic for every endpoint for the CertificateManagementAPI API.
// Include any external packages or services that will be required by this service.
type CertificateManagementAPIService struct {
	authorityRepo *db.AuthorityRepository
	log           *zap.Logger
}

// NewCertificateManagementAPIService creates a default api service
func NewCertificateManagementAPIService(authorityRepo *db.AuthorityRepository, logger *zap.Logger) CertificateManagementAPIServicer {
	return &CertificateManagementAPIService{
		authorityRepo: authorityRepo,
		log:           logger,
	}
}

// IdentifyCertificate - Identify Certificate
func (s *CertificateManagementAPIService) IdentifyCertificate(ctx context.Context, uuid string, certificateIdentificationRequestDto model.CertificateIdentificationRequestDto) (model.ImplResponse, error) {
	raAttributes := certificateIdentificationRequestDto.RaProfileAttributes
	engineName, err := getRAProfileEngineName(raAttributes)
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
	decoded, err := base64.StdEncoding.DecodeString(certificateIdentificationRequestDto.Certificate)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	serialNumber, err := utils.ExtractSerialNumber(decoded)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}

	s.log.With(zax.Get(ctx)...).Info("Identifying certificate with serial number: " + serialNumber)
	_, err = client.Secrets.PkiReadCert(ctx, serialNumber, vault2.WithMountPath(engineName+"/"))
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	response := model.CertificateIdentificationResponseDto{
		Meta: []model.MetadataAttribute{},
	}

	return model.Response(http.StatusOK, response), nil
}

// IssueCertificate - Issue Certificate
func (s *CertificateManagementAPIService) IssueCertificate(ctx context.Context, uuid string, certificateSignRequestDto model.CertificateSignRequestDto) (model.ImplResponse, error) {
	//TODO: refactor and merge code with renew certificate
	if certificateSignRequestDto.CertificateRequestFormat != model.CERTIFICATEREQUESTFORMAT_PKCS10 {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Invalid certificate request format, PKCS#10 format expected.",
		}), nil
	}

	raAttributes := certificateSignRequestDto.RaProfileAttributes
	engineName, err := getRAProfileEngineName(raAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		}), nil
	}
	role, err := getRAProfileRoleName(raAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileRoleMessage,
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
	decoded, err := base64.StdEncoding.DecodeString(certificateSignRequestDto.Request)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	commonName, err := utils.ExtractCommonName(decoded)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST", // Or "CERTIFICATE", depending on what's in the DER file
		Bytes: decoded,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	signRequest := schema.PkiSignWithRoleRequest{
		CommonName: commonName,
		Csr:        string(pemBytes),
	}

	s.log.With(zax.Get(ctx)...).Info("Issuing certificate", zap.String("common_name", commonName), zap.String("role", role), zap.String("engine_name", engineName))
	certificateSignResponse, err := client.Secrets.PkiSignWithRole(ctx, role, signRequest, vault2.WithMountPath(engineName+"/"))
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	certificate := certificateSignResponse.Data.Certificate
	serialNumber := certificateSignResponse.Data.SerialNumber
	pemBlock, _ = pem.Decode([]byte(certificate))
	if pemBlock == nil {
		s.log.With(zax.Get(ctx)...).Error("Failed to decode PEM file")
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to decode PEM file",
			}), nil

		}
	}
	derBytes := pemBlock.Bytes

	CertificateDataResponseDto := model.CertificateDataResponseDto{
		CertificateData: base64.StdEncoding.EncodeToString(derBytes),
		Uuid:            utils.DeterministicGUID(serialNumber),
		Meta:            nil,
		CertificateType: "X.509",
	}

	return model.Response(http.StatusOK, CertificateDataResponseDto), nil
}

// ListIssueCertificateAttributes - List of Attributes to issue Certificate
func (s *CertificateManagementAPIService) ListIssueCertificateAttributes(ctx context.Context, uuid string) (model.ImplResponse, error) {
	return model.Response(http.StatusOK, nil), nil
}

// ListRevokeCertificateAttributes - List of Attributes to revoke Certificate
func (s *CertificateManagementAPIService) ListRevokeCertificateAttributes(ctx context.Context, uuid string) (model.ImplResponse, error) {
	return model.Response(http.StatusOK, nil), nil
}

// RenewCertificate - Renew Certificate
func (s *CertificateManagementAPIService) RenewCertificate(ctx context.Context, uuid string, certificateRenewRequestDto model.CertificateRenewRequestDto) (model.ImplResponse, error) {
	if certificateRenewRequestDto.CertificateRequestFormat != model.CERTIFICATEREQUESTFORMAT_PKCS10 {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Invalid certificate request format, PKCS#10 format expected.",
		}), nil
	}

	raAttributes := certificateRenewRequestDto.RaProfileAttributes
	engineName, err := getRAProfileEngineName(raAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		}), nil
	}
	role, err := getRAProfileRoleName(raAttributes)
	if err != nil {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileRoleMessage,
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
	decoded, err := base64.StdEncoding.DecodeString(certificateRenewRequestDto.Request)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	commonName, err := utils.ExtractCommonName(decoded)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST", // Or "CERTIFICATE", depending on what's in the DER file
		Bytes: decoded,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	signRequest := schema.PkiSignWithRoleRequest{
		CommonName: commonName,
		Csr:        string(pemBytes),
	}

	s.log.With(zax.Get(ctx)...).Info("Renewing certificate", zap.String("common_name", commonName), zap.String("role", role), zap.String("engine_name", engineName))
	certificateSignResponse, err := client.Secrets.PkiSignWithRole(ctx, role, signRequest, vault2.WithMountPath(engineName+"/"))
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	certificate := certificateSignResponse.Data.Certificate
	serialNumber := certificateSignResponse.Data.SerialNumber
	pemBlock, _ = pem.Decode([]byte(certificate))
	if pemBlock == nil {
		s.log.With(zax.Get(ctx)...).Error("Failed to decode PEM file")
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
				Message: "Failed to decode PEM file",
			}), nil

		}
	}
	derBytes := pemBlock.Bytes

	CertificateDataResponseDto := model.CertificateDataResponseDto{
		CertificateData: base64.StdEncoding.EncodeToString(derBytes),
		Uuid:            utils.DeterministicGUID(serialNumber),
		Meta:            nil,
		CertificateType: "X.509",
	}

	return model.Response(http.StatusOK, CertificateDataResponseDto), nil
}

// RevokeCertificate - Revoke Certificate
func (s *CertificateManagementAPIService) RevokeCertificate(ctx context.Context, uuid string, certRevocationDto model.CertRevocationDto) (model.ImplResponse, error) {
	engineName, err := getRAProfileEngineName(certRevocationDto.RaProfileAttributes)
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
	decoded, err := base64.StdEncoding.DecodeString(certRevocationDto.Certificate)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST", // Or "CERTIFICATE", depending on what's in the DER file
		Bytes: decoded,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	revokeRequest := schema.PkiRevokeRequest{
		Certificate: string(pemBytes),
	}

	serialNumber, err := utils.ExtractSerialNumber(decoded)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}

	s.log.With(zax.Get(ctx)...).Info("Revoking certificate", zap.String("serial_number", serialNumber), zap.String("reason", string(certRevocationDto.Reason)), zap.String("engine_name", engineName))
	_, err = client.Secrets.PkiRevoke(ctx, revokeRequest, vault2.WithMountPath(engineName+"/"))
	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: err.Error(),
		}), nil

	}
	return model.Response(http.StatusOK, nil), nil

}

// ValidateIssueCertificateAttributes - Validate list of Attributes to issue Certificate
func (s *CertificateManagementAPIService) ValidateIssueCertificateAttributes(ctx context.Context, uuid string, requestAttributeDto []model.RequestAttributeDto) (model.ImplResponse, error) {
	s.log.With(zax.Get(ctx)...).Info("Validating issue certificate attributes", zap.String("uuid", uuid))
	return model.Response(http.StatusOK, nil), nil
}

// ValidateRevokeCertificateAttributes - Validate list of Attributes to revoke certificate
func (s *CertificateManagementAPIService) ValidateRevokeCertificateAttributes(ctx context.Context, uuid string, requestAttributeDto []model.RequestAttributeDto) (model.ImplResponse, error) {
	s.log.With(zax.Get(ctx)...).Info("Validating revoke certificate attributes", zap.String("uuid", uuid))
	return model.Response(http.StatusOK, nil), nil
}
