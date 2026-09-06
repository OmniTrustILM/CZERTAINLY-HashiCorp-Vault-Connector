package health

import (
	"context"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"net/http"
)

// HealthCheckAPIRouter defines the required methods for binding the api requests to a responses for the HealthCheckAPI
// The HealthCheckAPIRouter implementation should parse necessary information from the http request,
// pass the data to a HealthCheckAPIServicer to perform the required actions, then write the service results to the http response.
type HealthCheckAPIRouter interface {
	CheckHealth(http.ResponseWriter, *http.Request)
}

// HealthCheckAPIServicer defines the api actions for the HealthCheckAPI service
// This interface intended to stay up to date with the openapi yaml used to generate it,
// while the service implementation can be ignored with the .openapi-generator-ignore file
// and updated with the logic required for the API.
type HealthCheckAPIServicer interface {
	CheckHealth(context.Context) (model.ImplResponse, error)
}
