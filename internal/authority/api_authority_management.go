package authority

import (
	"CZERTAINLY-HashiCorp-Vault-Connector/internal/model"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// AuthorityManagementAPIController binds http requests to an api service and writes the service results to the http response
type AuthorityManagementAPIController struct {
	service      AuthorityManagementAPIServicer
	errorHandler model.ErrorHandler
}

// AuthorityManagementAPIOption for how the controller is set up.
type AuthorityManagementAPIOption func(*AuthorityManagementAPIController)

// WithAuthorityManagementAPIErrorHandler inject model.ErrorHandler into controller
func WithAuthorityManagementAPIErrorHandler(h model.ErrorHandler) AuthorityManagementAPIOption {
	return func(c *AuthorityManagementAPIController) {
		c.errorHandler = h
	}
}

// NewAuthorityManagementAPIController creates a default api controller
func NewAuthorityManagementAPIController(s AuthorityManagementAPIServicer, opts ...AuthorityManagementAPIOption) model.Router {
	controller := &AuthorityManagementAPIController{
		service:      s,
		errorHandler: model.DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the AuthorityManagementAPIController
func (c *AuthorityManagementAPIController) Routes() model.Routes {
	return model.Routes{
		"CreateAuthorityInstance": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/authorities",
			HandlerFunc: c.CreateAuthorityInstance,
		},
		"GetAuthorityInstance": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}",
			HandlerFunc: c.GetAuthorityInstance,
		},
		"GetCaCertificates": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/caCertificates",
			HandlerFunc: c.GetCaCertificates,
		},
		"GetConnection": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/connect",
			HandlerFunc: c.GetConnection,
		},
		"GetCrl": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/crl",
			HandlerFunc: c.GetCrl,
		},
		"ListAuthorityInstances": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/authorities",
			HandlerFunc: c.ListAuthorityInstances,
		},
		"ListRAProfileAttributes": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/raProfile/attributes",
			HandlerFunc: c.ListRAProfileAttributes,
		},
		"RemoveAuthorityInstance": model.Route{
			Method:      strings.ToUpper("Delete"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}",
			HandlerFunc: c.RemoveAuthorityInstance,
		},
		"UpdateAuthorityInstance": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}",
			HandlerFunc: c.UpdateAuthorityInstance,
		},
		"ValidateRAProfileAttributes": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/raProfile/attributes/validate",
			HandlerFunc: c.ValidateRAProfileAttributes,
		},
		"RAProfileCallback": model.Route{
			Method: strings.ToUpper("Get"),
			// {engineName:.*} so nested Vault mount paths (e.g. team/pki-root) round-trip;
			// the default mux pattern would not match a value containing '/'.
			Pattern:     "/v1/authorityProvider/authorities/{uuid}/raProfileRole/{engineName:.*}/callback",
			HandlerFunc: c.RAProfileCallback,
		},
	}
}

// CreateAuthorityInstance - Create Authority instance
func (c *AuthorityManagementAPIController) CreateAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	authorityProviderInstanceRequestDtoParam := &model.AuthorityProviderInstanceRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	authorityProviderInstanceRequestDtoParam.Unmarshal(jsonContent)

	if err := model.AssertAuthorityProviderInstanceRequestDtoRequired(*authorityProviderInstanceRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertAuthorityProviderInstanceRequestDtoConstraints(*authorityProviderInstanceRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}

	result, err := c.service.CreateAuthorityInstance(r.Context(), *authorityProviderInstanceRequestDtoParam)
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

// GetAuthorityInstance - Get an Authority instance
func (c *AuthorityManagementAPIController) GetAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.GetAuthorityInstance(r.Context(), uuidParam)
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

// GetCaCertificates - Get the Authority Instance's certificate chain
func (c *AuthorityManagementAPIController) GetCaCertificates(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	caCertificatesRequestDtoParam := model.CaCertificatesRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	caCertificatesRequestDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCaCertificatesRequestDtoRequired(caCertificatesRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCaCertificatesRequestDtoConstraints(caCertificatesRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.GetCaCertificates(r.Context(), uuidParam, caCertificatesRequestDtoParam)
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

// GetConnection - Connect to Authority
func (c *AuthorityManagementAPIController) GetConnection(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.GetConnection(r.Context(), uuidParam)
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

// GetCrl - Get the latest CRL for the Authority Instance
func (c *AuthorityManagementAPIController) GetCrl(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	certificateRevocationListRequestDtoParam := model.CertificateRevocationListRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	certificateRevocationListRequestDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCertificateRevocationListRequestDtoRequired(certificateRevocationListRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCertificateRevocationListRequestDtoConstraints(certificateRevocationListRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.GetCrl(r.Context(), uuidParam, certificateRevocationListRequestDtoParam)
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

// ListAuthorityInstances - List Authority instances
func (c *AuthorityManagementAPIController) ListAuthorityInstances(w http.ResponseWriter, r *http.Request) {
	result, err := c.service.ListAuthorityInstances(r.Context())
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

// ListRAProfileAttributes - List RA Profile Attributes
func (c *AuthorityManagementAPIController) ListRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.ListRAProfileAttributes(r.Context(), uuidParam)
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

// RemoveAuthorityInstance - Remove Authority instance
func (c *AuthorityManagementAPIController) RemoveAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.RemoveAuthorityInstance(r.Context(), uuidParam)
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

// UpdateAuthorityInstance - Update Authority instance
func (c *AuthorityManagementAPIController) UpdateAuthorityInstance(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	authorityProviderInstanceRequestDtoParam := &model.AuthorityProviderInstanceRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	authorityProviderInstanceRequestDtoParam.Unmarshal(jsonContent)
	result, err := c.service.UpdateAuthorityInstance(r.Context(), uuidParam, *authorityProviderInstanceRequestDtoParam)
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

// ValidateRAProfileAttributes - Validate RA Profile attributes
func (c *AuthorityManagementAPIController) ValidateRAProfileAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	var requestAttributeDtoParam []model.RequestAttributeDto
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}
	model.UnmarshalAttributesValues(jsonContent)
	for _, el := range requestAttributeDtoParam {
		if err := model.AssertRequestAttributeDtoRequired(el); err != nil {
			c.errorHandler(w, r, err, nil)
			return
		}
	}
	result, err := c.service.ValidateRAProfileAttributes(r.Context(), uuidParam, requestAttributeDtoParam)
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

// RAProfileCallback - Validate RA Profile attributes
func (c *AuthorityManagementAPIController) RAProfileCallback(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	engineName := params["engineName"]
	if engineName == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "engineName"}, nil)
		return
	}

	result, err := c.service.RAProfileCallback(r.Context(), uuidParam, engineName)
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
