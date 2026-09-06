package discovery

import (
	"context"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"net/http"
)

// ConnectorAttributesAPIRouter defines the required methods for binding the api requests to a responses for the ConnectorAttributesAPI
// The ConnectorAttributesAPIRouter implementation should parse necessary information from the http request,
// pass the data to a ConnectorAttributesAPIServicer to perform the required actions, then write the service results to the http response.
type ConnectorAttributesAPIRouter interface {
	ListAttributeDefinitions(http.ResponseWriter, *http.Request)
	ValidateAttributes(http.ResponseWriter, *http.Request)
	PkiEnginesCallback(http.ResponseWriter, *http.Request)
}

// DiscoveryAPIRouter defines the required methods for binding the api requests to a responses for the DiscoveryAPI
// The DiscoveryAPIRouter implementation should parse necessary information from the http request,
// pass the data to a DiscoveryAPIServicer to perform the required actions, then write the service results to the http response.
type DiscoveryAPIRouter interface {
	DeleteDiscovery(http.ResponseWriter, *http.Request)
	DiscoverCertificate(http.ResponseWriter, *http.Request)
	GetDiscovery(http.ResponseWriter, *http.Request)
}

// ConnectorAttributesAPIServicer defines the api actions for the ConnectorAttributesAPI service
// This interface intended to stay up to date with the openapi yaml used to generate it,
// while the service implementation can be ignored with the .openapi-generator-ignore file
// and updated with the logic required for the API.
type ConnectorAttributesAPIServicer interface {
	ListAttributeDefinitions(context.Context, string) (model.ImplResponse, error)
	ValidateAttributes(context.Context, string, []model.Attribute) (model.ImplResponse, error)
	PkiEnginesCallback(context.Context, string) (model.ImplResponse, error)
}

// DiscoveryAPIServicer defines the api actions for the DiscoveryAPI service
// This interface intended to stay up to date with the openapi yaml used to generate it,
// while the service implementation can be ignored with the .openapi-generator-ignore file
// and updated with the logic required for the API.
type DiscoveryAPIServicer interface {
	DeleteDiscovery(context.Context, string) (model.ImplResponse, error)
	DiscoverCertificate(context.Context, model.DiscoveryRequestDto) (model.ImplResponse, error)
	GetDiscovery(context.Context, string, model.DiscoveryDataRequestDto) (model.ImplResponse, error)
}
