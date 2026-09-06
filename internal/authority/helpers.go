package authority

import (
	"encoding/json"
	"net/http"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/utils"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/vault"
	vault2 "github.com/hashicorp/vault-client-go"
)

// This file collects the response-building steps that were duplicated,
// nearly verbatim, across the certificate and authority management
// services: resolving the RA profile engine/role, looking up the stored
// authority, opening a Vault client for it, and building the CA-chain and
// attribute-extraction shapes used by more than one endpoint. Each helper
// mirrors exactly the inline code it replaces, including which status code
// and message it reports on failure, so callers that used to differ in
// wording or status intentionally keep their own inline handling instead of
// being forced through one of these.

// resolveEngineName extracts the PKI engine name from the RA profile
// attributes, returning the bad-request response used throughout this
// package whenever the attribute is missing or invalid.
func resolveEngineName(raAttributes []model.Attribute) (string, *model.ImplResponse) {
	engineName, err := getRAProfileEngineName(raAttributes)
	if err != nil {
		resp := model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileEngineMessage,
		})
		return "", &resp
	}
	return engineName, nil
}

// resolveRoleName extracts the PKI role name from the RA profile
// attributes, returning the bad-request response used throughout this
// package whenever the attribute is missing or invalid.
func resolveRoleName(raAttributes []model.Attribute) (string, *model.ImplResponse) {
	role, err := getRAProfileRoleName(raAttributes)
	if err != nil {
		resp := model.Response(http.StatusBadRequest, model.ErrorMessageDto{
			Message: invalidRAProfileRoleMessage,
		})
		return "", &resp
	}
	return role, nil
}

// authorityRepository is the subset of *db.AuthorityRepository's methods
// that findAuthority and the services in this package call. Depending on
// this interface instead of the concrete repository type lets tests
// substitute a fake and exercise service logic - the not-found path, and
// anything that runs before or after the Vault call - without a live
// database.
type authorityRepository interface {
	FindAuthorityInstanceByUUID(uuid string) (*db.AuthorityInstance, error)
	FindAuthorityInstanceByName(name string) (*db.AuthorityInstance, error)
	CreateAuthorityInstance(authority *db.AuthorityInstance) error
	UpdateAuthorityInstance(authority *db.AuthorityInstance) error
	DeleteAuthorityInstance(authority *db.AuthorityInstance) error
	ListAuthorityInstances() ([]*db.AuthorityInstance, error)
}

// findAuthority looks up the stored authority instance by uuid, returning
// the not-found response used by the certificate and CA-chain operations in
// this package when it does not exist. GetConnection and
// UpdateAuthorityInstance report this same lookup failing as an internal
// error instead, so they deliberately keep their own inline check rather
// than calling this helper.
func findAuthority(authorityRepo authorityRepository, uuid string) (*db.AuthorityInstance, *model.ImplResponse) {
	authority, err := authorityRepo.FindAuthorityInstanceByUUID(uuid)
	if err != nil {
		resp := model.Response(http.StatusNotFound, model.ErrorMessageDto{
			Message: "Authority not found",
		})
		return nil, &resp
	}
	return authority, nil
}

// connectVault opens a Vault client for the authority, returning the
// internal-error response used throughout this package when the connection
// fails.
func connectVault(authority db.AuthorityInstance) (*vault2.Client, *model.ImplResponse) {
	client, err := vault.GetClient(authority)
	if err != nil {
		resp := model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: err.Error(),
		})
		return nil, &resp
	}
	return client, nil
}

// certificateChainResponse builds the CA-chain response DTO shared by
// GetCaCertificates and GetCrl from a list of DER-encoded certificates.
func certificateChainResponse(chain []string) model.CaCertificatesResponseDto {
	var certificates []model.CertificateDataResponseDto
	for _, cert := range chain {
		certificates = append(certificates, model.CertificateDataResponseDto{
			CertificateData: cert,
			Uuid:            utils.DeterministicGUID(),
			Meta:            nil,
			CertificateType: "X.509",
		})
	}
	return model.CaCertificatesResponseDto{Certificates: certificates}
}

// optionalStringAttribute returns the string value of the first content
// item for the attribute identified by attrUUID, or "" if the attribute is
// not present. As in the inline code it replaces, a present attribute whose
// content is not a string is not guarded against and will panic.
func optionalStringAttribute(attrUUID string, attributes []model.Attribute) string {
	attr := model.GetAttributeFromArrayByUUID(attrUUID, attributes)
	if attr == nil {
		return ""
	}
	return attr.GetContent()[0].GetData().(string)
}

// secretAttributeValue returns the secret held by the SecretAttributeContent
// of the attribute identified by attrUUID. Callers are expected to only use
// this where the attribute is known to be present, matching the inline code
// this replaces.
func secretAttributeValue(attrUUID string, attributes []model.Attribute) string {
	content := model.GetAttributeFromArrayByUUID(attrUUID, attributes).GetContent()[0]
	return content.(model.SecretAttributeContent).GetData().(model.SecretAttributeContentData).Secret
}

// marshalAttributes marshals the attributes to JSON, returning the
// internal-error response used by CreateAuthorityInstance and
// UpdateAuthorityInstance when marshaling fails. The underlying error is
// also returned (rather than nil) because, unlike the other helpers in this
// file, the inline code it replaces propagated it as the servicer's own
// error return value.
func marshalAttributes(attributes []model.Attribute) ([]byte, *model.ImplResponse, error) {
	marshaled, err := json.Marshal(attributes)
	if err != nil {
		resp := model.Response(http.StatusInternalServerError, model.ErrorMessageDto{
			Message: "Failed to marshal attributes",
		})
		return nil, &resp, err
	}
	return marshaled, nil, nil
}
