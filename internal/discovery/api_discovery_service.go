package discovery

import (
	"context"
	"encoding/base64"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/vault"
	"net/http"
	"strings"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	vault2 "github.com/hashicorp/vault-client-go"
	"go.uber.org/zap"
)

// discoveryRepository is the subset of *db.DiscoveryRepository's methods that
// DiscoveryAPIService calls. Depending on this interface instead of the
// concrete repository type lets tests substitute a fake and exercise service
// logic without a live database.
type discoveryRepository interface {
	FindDiscoveryByUUID(uuid string) (*db.Discovery, error)
	CreateDiscovery(discovery *db.Discovery) error
	DeleteDiscovery(discovery *db.Discovery) error
	UpdateDiscovery(discovery *db.Discovery) error
	AssociateCertificatesToDiscovery(discovery *db.Discovery, certificates ...*db.Certificate) error
	List(pagination db.Pagination, discovery *db.Discovery) (*db.Pagination, error)
}

// authorityRepository is the subset of *db.AuthorityRepository's methods that
// DiscoveryAPIService calls, for the same reason.
type authorityRepository interface {
	FindAuthorityInstanceByUUID(uuid string) (*db.AuthorityInstance, error)
	ListAuthorityInstances() ([]*db.AuthorityInstance, error)
}

// failDiscovery marks the discovery as failed and persists it.
func (s *DiscoveryAPIService) failDiscovery(ctx context.Context, discovery *db.Discovery, reason string) {
	s.log.With(logger.Fields(ctx)...).Error(reason)
	discovery.Status = "FAILED"

	if err := s.discoveryRepo.UpdateDiscovery(discovery); err != nil {
		s.log.With(logger.Fields(ctx)...).Error(err.Error())
	}
}

// DiscoveryAPIService is a service that implements the logic for the DiscoveryAPIServicer
// This service should implement the business logic for every endpoint for the DiscoveryAPI API.
// Include any external packages or services that will be required by this service.
type DiscoveryAPIService struct {
	discoveryRepo discoveryRepository
	authorityRepo authorityRepository
	log           *zap.Logger
}

// NewDiscoveryAPIService creates a default api service
func NewDiscoveryAPIService(discoveryRepo *db.DiscoveryRepository, authorityRepo *db.AuthorityRepository, logger *zap.Logger) DiscoveryAPIServicer {
	return &DiscoveryAPIService{
		discoveryRepo: discoveryRepo,
		authorityRepo: authorityRepo,
		log:           logger,
	}
}

// DeleteDiscovery - Delete Discovery
func (s *DiscoveryAPIService) DeleteDiscovery(ctx context.Context, uuid string) (model.ImplResponse, error) {
	discovery, err := s.discoveryRepo.FindDiscoveryByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Discovery " + uuid + " not found."}), nil
	}

	s.log.With(logger.Fields(ctx)...).Info("Deleting discovery", zap.String("discovery_uuid", discovery.UUID))
	err = s.discoveryRepo.DeleteDiscovery(discovery)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{Message: "Unable to delete discover" + discovery.UUID}), nil
	}

	return model.Response(204, nil), nil
}

// DiscoverCertificate - Initiate certificate Discovery
func (s *DiscoveryAPIService) DiscoverCertificate(ctx context.Context, discoveryRequestDto model.DiscoveryRequestDto) (model.ImplResponse, error) {
	response := model.DiscoveryProviderDto{
		Uuid:                        utils.DeterministicGUID(discoveryRequestDto.Name),
		Name:                        discoveryRequestDto.Name,
		Status:                      model.IN_PROGRESS,
		TotalCertificatesDiscovered: 0,
		CertificateData:             nil,
		Meta:                        nil,
	}
	discovery := &db.Discovery{
		UUID:         response.Uuid,
		Name:         response.Name,
		Status:       string(response.Status),
		Meta:         nil,
		Certificates: nil,
	}

	uuid := model.GetAttributeFromArrayByUUID(model.DISCOVERY_AUTHORITY_ATTR, discoveryRequestDto.Attributes).GetContent()[0].GetData().(map[string]any)["uuid"].(string)

	authority, err := s.authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Authority not found " + uuid}), nil
	}

	enginesAttr := model.GetAttributeFromArrayByUUID(model.DISCOVERY_PKI_ENGINE_ATTR, discoveryRequestDto.Attributes)
	var enginesList []string
	if enginesAttr == nil {
		s.log.With(logger.Fields(ctx)...).Info("No PKI engines specified for discovery, trying to get all available engines")
		// get the vault client
		client, err := vault.GetClient(*authority)
		if err != nil {
			discovery.Status = "FAILED"
			err := s.discoveryRepo.UpdateDiscovery(discovery)
			if err != nil {
				s.log.With(logger.Fields(ctx)...).Error(err.Error())
			}
			s.log.With(logger.Fields(ctx)...).Error(err.Error())
			return model.Response(http.StatusBadRequest, model.ErrorMessageDto{Message: "Unable to create vault client"}), nil
		}
		ctx := context.Background()
		//Due to the nature of its intended usage, there is no guarantee on backwards compatibility for this endpoint.
		mounts, _ := client.System.InternalUiListEnabledVisibleMounts(ctx)
		for engineName, engineData := range mounts.Data.Secret {
			engineName = strings.TrimSuffix(engineName, "/")
			if engineData.(map[string]any)["type"] == "pki" {
				enginesList = append(enginesList, engineName)
			}
		}
	} else {
		enginesList = make([]string, 0)
		for _, engine := range enginesAttr.GetContent() {
			engineData := engine.(model.ObjectAttributeContent).GetData().(map[string]any)
			engineName := engineData["engineName"].(string)
			enginesList = append(enginesList, engineName)
		}
	}

	err = s.discoveryRepo.CreateDiscovery(discovery)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Unable to create discovery " + discovery.UUID}), nil
	}

	s.log.With(logger.Fields(ctx)...).Info("Starting discovery of certificates", zap.String("discovery_uuid", discovery.UUID), zap.String("authority_uuid", authority.UUID))
	go s.DiscoveryCertificates(ctx, authority, discovery, enginesList)

	return model.Response(http.StatusOK, response), nil
}

// GetDiscovery - Get Discovery status and result
func (s *DiscoveryAPIService) GetDiscovery(ctx context.Context, uuid string, discoveryDataRequestDto model.DiscoveryDataRequestDto) (model.ImplResponse, error) {
	discovery, err := s.discoveryRepo.FindDiscoveryByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Discovery " + uuid + " not found."}), nil
	}
	if discovery.Status == "IN_PROGRESS" {
		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.IN_PROGRESS, TotalCertificatesDiscovered: 0, CertificateData: []model.DiscoveryProviderCertificateDataDto{}, Meta: []model.MetadataAttribute{}}), nil
	} else {
		pagination := db.Pagination{
			Page:  int(discoveryDataRequestDto.PageNumber),
			Limit: int(discoveryDataRequestDto.ItemsPerPage),
		}
		result, _ := s.discoveryRepo.List(pagination, discovery)
		var certificateDtos []model.DiscoveryProviderCertificateDataDto
		rows, _ := result.Rows.([]db.Certificate)
		for _, certificateData := range rows {
			discoveryProviderCertificateDataDto := model.DiscoveryProviderCertificateDataDto{
				Uuid:          certificateData.UUID,
				Base64Content: certificateData.Base64Content,
				Meta:          []model.MetadataAttribute{}, //empty array
			}
			certificateDtos = append(certificateDtos, discoveryProviderCertificateDataDto)
		}

		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.COMPLETED, TotalCertificatesDiscovered: result.TotalRows, CertificateData: certificateDtos, Meta: []model.MetadataAttribute{}}), nil
	}

}

func (s *DiscoveryAPIService) DiscoveryCertificates(ctx context.Context, authority *db.AuthorityInstance, discovery *db.Discovery, list []string) {
	// get the vault client
	client, err := vault.GetClient(*authority)
	if err != nil {
		s.failDiscovery(ctx, discovery, err.Error())
		return
	}

	if len(list) == 0 {
		s.log.With(logger.Fields(ctx)...).Info("No PKI engines available for discovery")
	} else {
		for _, engine := range list {
			s.log.With(logger.Fields(ctx)...).Info("Discovering certificates", zap.String("engine", engine))
			certificates, err := client.Secrets.PkiListCerts(ctx, vault2.WithMountPath(engine))
			if err != nil {
				discovery.Status = "FAILED"
				err := s.discoveryRepo.UpdateDiscovery(discovery)
				if err != nil {
					s.log.With(logger.Fields(ctx)...).Error(err.Error())
				}
				return
			}
			var certificateKeys []*db.Certificate
			for _, certificateKey := range certificates.Data.Keys {
				s.log.With(logger.Fields(ctx)...).Debug("Reading certificate", zap.String("certificate_key", certificateKey), zap.String("engine", engine))
				certificateData, err := client.Secrets.PkiReadCert(ctx, certificateKey, vault2.WithMountPath(engine))
				if err != nil {
					discovery.Status = "FAILED"
					s.log.With(logger.Fields(ctx)...).Error("Error reading certificate", zap.String("certificate_key", certificateKey), zap.String("engine", engine), zap.Error(err))
					err := s.discoveryRepo.UpdateDiscovery(discovery)
					if err != nil {
						s.log.With(logger.Fields(ctx)...).Error(err.Error())
					}

					return
				}
				certificate := db.Certificate{
					SerialNumber:  certificateKey,
					UUID:          utils.DeterministicGUID(certificateKey),
					Base64Content: base64.StdEncoding.EncodeToString([]byte(certificateData.Data.Certificate)),
				}
				certificateKeys = append(certificateKeys, &certificate)
			}
			err = s.discoveryRepo.AssociateCertificatesToDiscovery(discovery, certificateKeys...)
			if err != nil {
				s.failDiscovery(ctx, discovery, err.Error())
				return
			}
		}
	}
	// Update discovery status to "COMPLETED"
	discovery.Status = "COMPLETED"
	err = s.discoveryRepo.UpdateDiscovery(discovery)
	if err != nil {
		s.failDiscovery(ctx, discovery, err.Error())
		return
	}

	s.log.With(logger.Fields(ctx)...).Info("Discovery completed", zap.String("discovery_uuid", discovery.UUID), zap.String("authority_uuid", authority.UUID), zap.Int("total_certificates", len(discovery.Certificates)))
}
