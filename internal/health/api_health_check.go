package health

import (
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"net/http"
	"strings"
)

// HealthCheckAPIController binds http requests to an api service and writes the service results to the http response
type HealthCheckAPIController struct {
	service      HealthCheckAPIServicer
	errorHandler model.ErrorHandler
}

// HealthCheckAPIOption for how the controller is set up.
type HealthCheckAPIOption func(*HealthCheckAPIController)

// WithHealthCheckAPIErrorHandler inject model.ErrorHandler into controller
func WithHealthCheckAPIErrorHandler(h model.ErrorHandler) HealthCheckAPIOption {
	return func(c *HealthCheckAPIController) {
		c.errorHandler = h
	}
}

// NewHealthCheckAPIController creates a default api controller
func NewHealthCheckAPIController(s HealthCheckAPIServicer, opts ...HealthCheckAPIOption) model.Router {
	controller := &HealthCheckAPIController{
		service:      s,
		errorHandler: model.DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the HealthCheckAPIController
func (c *HealthCheckAPIController) Routes() model.Routes {
	return model.Routes{
		"CheckHealth": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/health",
			HandlerFunc: c.CheckHealth,
		},
	}
}

// CheckHealth - Health check
func (c *HealthCheckAPIController) CheckHealth(w http.ResponseWriter, r *http.Request) {
	result, err := c.service.CheckHealth(r.Context())
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	err = model.EncodeJSONResponse(result.Body, &result.Code, w)
	if err != nil {
		return
	}
}
