package discovery

import (
	"encoding/json"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// DiscoveryAPIController binds http requests to an api service and writes the service results to the http response
type DiscoveryAPIController struct {
	service      DiscoveryAPIServicer
	errorHandler model.ErrorHandler
}

// DiscoveryAPIOption for how the controller is set up.
type DiscoveryAPIOption func(*DiscoveryAPIController)

// WithDiscoveryAPIErrorHandler inject model.ErrorHandler into controller
func WithDiscoveryAPIErrorHandler(h model.ErrorHandler) DiscoveryAPIOption {
	return func(c *DiscoveryAPIController) {
		c.errorHandler = h
	}
}

// NewDiscoveryAPIController creates a default api controller
func NewDiscoveryAPIController(s DiscoveryAPIServicer, opts ...DiscoveryAPIOption) model.Router {
	controller := &DiscoveryAPIController{
		service:      s,
		errorHandler: model.DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the DiscoveryAPIController
func (c *DiscoveryAPIController) Routes() model.Routes {
	return model.Routes{
		"DeleteDiscovery": model.Route{
			Method:      strings.ToUpper("Delete"),
			Pattern:     "/v1/discoveryProvider/discover/{uuid}",
			HandlerFunc: c.DeleteDiscovery,
		},
		"DiscoverCertificate": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/discoveryProvider/discover",
			HandlerFunc: c.DiscoverCertificate,
		},
		"GetDiscovery": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/discoveryProvider/discover/{uuid}",
			HandlerFunc: c.GetDiscovery,
		},
	}
}

// DeleteDiscovery - Delete Discovery
func (c *DiscoveryAPIController) DeleteDiscovery(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.DeleteDiscovery(r.Context(), uuidParam)
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

// DiscoverCertificate - Initiate certificate Discovery
func (c *DiscoveryAPIController) DiscoverCertificate(w http.ResponseWriter, r *http.Request) {
	discoveryRequestDtoParam := model.DiscoveryRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)

	discoveryRequestDtoParam.Unmarshal(jsonContent)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	if err := model.AssertDiscoveryRequestDtoRequired(discoveryRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertDiscoveryRequestDtoConstraints(discoveryRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}

	result, err := c.service.DiscoverCertificate(r.Context(), discoveryRequestDtoParam)
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

// GetDiscovery - Get Discovery status and result
func (c *DiscoveryAPIController) GetDiscovery(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	discoveryDataRequestDtoParam := model.DiscoveryDataRequestDto{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&discoveryDataRequestDtoParam); err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}
	if err := model.AssertDiscoveryDataRequestDtoRequired(discoveryDataRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertDiscoveryDataRequestDtoConstraints(discoveryDataRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.GetDiscovery(r.Context(), uuidParam, discoveryDataRequestDtoParam)
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
