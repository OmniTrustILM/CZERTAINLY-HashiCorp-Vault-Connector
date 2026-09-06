package connectorInfo

import (
	"context"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"net/http"
)

// ConnectorInfoAPIRouter defines the required methods for binding the api requests to a responses for the ConnectorInfoAPI
// The ConnectorInfoAPIRouter implementation should parse necessary information from the http request,
// pass the data to a ConnectorInfoAPIServicer to perform the required actions, then write the service results to the http response.
type ConnectorInfoAPIRouter interface {
	ListSupportedFunctions(http.ResponseWriter, *http.Request)
}

// ConnectorInfoAPIServicer defines the api actions for the ConnectorInfoAPI service
// This interface intended to stay up to date with the openapi yaml used to generate it,
// while the service implementation can be ignored with the .openapi-generator-ignore file
// and updated with the logic required for the API.
type ConnectorInfoAPIServicer interface {
	ListSupportedFunctions(context.Context) (model.ImplResponse, error)
}
