package authority

import (
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// ConnectorAttributesAPIController binds http requests to an api service and writes the service results to the http response
type ConnectorAttributesAPIController struct {
	service      ConnectorAttributesAPIServicer
	errorHandler model.ErrorHandler
}

// ConnectorAttributesAPIOption for how the controller is set up.
type ConnectorAttributesAPIOption func(*ConnectorAttributesAPIController)

// WithConnectorAttributesAPIErrorHandler inject model.ErrorHandler into controller
func WithConnectorAttributesAPIErrorHandler(h model.ErrorHandler) ConnectorAttributesAPIOption {
	return func(c *ConnectorAttributesAPIController) {
		c.errorHandler = h
	}
}

// NewConnectorAttributesAPIController creates a default api controller
func NewConnectorAttributesAPIController(s ConnectorAttributesAPIServicer, opts ...ConnectorAttributesAPIOption) model.Router {
	controller := &ConnectorAttributesAPIController{
		service:      s,
		errorHandler: model.DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the ConnectorAttributesAPIController
func (c *ConnectorAttributesAPIController) Routes() model.Routes {
	return model.Routes{
		"ListAttributeDefinitions": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/{kind}/attributes",
			HandlerFunc: c.ListAttributeDefinitions,
		},
		"Callback": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/credentialType/{credentialType}/callback",
			HandlerFunc: c.CredentialAttributesCallback,
		},
		"ValidateAttributes": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/{kind}/attributes/validate",
			HandlerFunc: c.ValidateAttributes,
		},
	}
}

// ListAttributeDefinitions - List available Attributes
func (c *ConnectorAttributesAPIController) ListAttributeDefinitions(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	kindParam := params["kind"]
	if kindParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "kind"}, nil)
		return
	}
	result, err := c.service.ListAttributeDefinitions(r.Context(), kindParam)
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

func (c *ConnectorAttributesAPIController) CredentialAttributesCallback(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	credentialType := params["credentialType"]
	if credentialType == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "credentialType"}, nil)
		return
	}
	result, err := c.service.CredentialAttributesCallback(r.Context(), credentialType)
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

// ValidateAttributes - Validate Attributes
func (c *ConnectorAttributesAPIController) ValidateAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	kindParam := params["kind"]
	if kindParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "kind"}, nil)
		return
	}
	json, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}
	attributes := model.UnmarshalAttributesValues(json)
	result, err := c.service.ValidateAttributes(r.Context(), kindParam, attributes)
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
