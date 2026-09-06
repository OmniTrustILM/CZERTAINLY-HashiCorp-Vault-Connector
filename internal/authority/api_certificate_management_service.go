package authority

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
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
	engineName, errResp := resolveEngineName(certificateIdentificationRequestDto.RaProfileAttributes)
	if errResp != nil {
		return *errResp, nil
	}
	authority, errResp := findAuthority(s.authorityRepo, uuid)
	if errResp != nil {
		return *errResp, nil
	}
	client, errResp := connectVault(*authority)
	if errResp != nil {
		return *errResp, nil
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

// signOrRenewCertificate implements the flow shared by IssueCertificate and
// RenewCertificate: both submit a PKCS#10 request to Vault's PKI secrets
// engine and return the resulting leaf certificate in the same response
// shape. action names the operation for the info log ("Issuing certificate"
// vs "Renewing certificate").
func (s *CertificateManagementAPIService) signOrRenewCertificate(ctx context.Context, uuid, action string, format model.CertificateRequestFormat, raAttributes []model.Attribute, requestB64 string) (model.ImplResponse, error) {
	if format != model.CERTIFICATEREQUESTFORMAT_PKCS10 {
		return model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: "Invalid certificate request format, PKCS#10 format expected.",
		}), nil
	}

	engineName, errResp := resolveEngineName(raAttributes)
	if errResp != nil {
		return *errResp, nil
	}
	role, errResp := resolveRoleName(raAttributes)
	if errResp != nil {
		return *errResp, nil
	}
	authority, errResp := findAuthority(s.authorityRepo, uuid)
	if errResp != nil {
		return *errResp, nil
	}
	client, errResp := connectVault(*authority)
	if errResp != nil {
		return *errResp, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(requestB64)
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

	s.log.With(zax.Get(ctx)...).Info(action, zap.String("common_name", commonName), zap.String("role", role), zap.String("engine_name", engineName))
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

// IssueCertificate - Issue Certificate
func (s *CertificateManagementAPIService) IssueCertificate(ctx context.Context, uuid string, certificateSignRequestDto model.CertificateSignRequestDto) (model.ImplResponse, error) {
	return s.signOrRenewCertificate(ctx, uuid, "Issuing certificate",
		certificateSignRequestDto.CertificateRequestFormat, certificateSignRequestDto.RaProfileAttributes, certificateSignRequestDto.Request)
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
	return s.signOrRenewCertificate(ctx, uuid, "Renewing certificate",
		certificateRenewRequestDto.CertificateRequestFormat, certificateRenewRequestDto.RaProfileAttributes, certificateRenewRequestDto.Request)
}

// RevokeCertificate - Revoke Certificate
func (s *CertificateManagementAPIService) RevokeCertificate(ctx context.Context, uuid string, certRevocationDto model.CertRevocationDto) (model.ImplResponse, error) {
	engineName, errResp := resolveEngineName(certRevocationDto.RaProfileAttributes)
	if errResp != nil {
		return *errResp, nil
	}
	authority, errResp := findAuthority(s.authorityRepo, uuid)
	if errResp != nil {
		return *errResp, nil
	}
	client, errResp := connectVault(*authority)
	if errResp != nil {
		return *errResp, nil
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
