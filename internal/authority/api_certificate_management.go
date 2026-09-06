package authority

import (
	"encoding/json"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// CertificateManagementAPIController binds http requests to an api service and writes the service results to the http response
type CertificateManagementAPIController struct {
	service      CertificateManagementAPIServicer
	errorHandler model.ErrorHandler
}

// CertificateManagementAPIOption for how the controller is set up.
type CertificateManagementAPIOption func(*CertificateManagementAPIController)

// WithCertificateManagementAPIErrorHandler inject model.ErrorHandler into controller
func WithCertificateManagementAPIErrorHandler(h model.ErrorHandler) CertificateManagementAPIOption {
	return func(c *CertificateManagementAPIController) {
		c.errorHandler = h
	}
}

// NewCertificateManagementAPIController creates a default api controller
func NewCertificateManagementAPIController(s CertificateManagementAPIServicer, opts ...CertificateManagementAPIOption) model.Router {
	controller := &CertificateManagementAPIController{
		service:      s,
		errorHandler: model.DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the CertificateManagementAPIController
func (c *CertificateManagementAPIController) Routes() model.Routes {
	return model.Routes{
		"IdentifyCertificate": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/identify",
			HandlerFunc: c.IdentifyCertificate,
		},
		"IssueCertificate": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/issue",
			HandlerFunc: c.IssueCertificate,
		},
		"ListIssueCertificateAttributes": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes",
			HandlerFunc: c.ListIssueCertificateAttributes,
		},
		"ListRevokeCertificateAttributes": model.Route{
			Method:      strings.ToUpper("Get"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes",
			HandlerFunc: c.ListRevokeCertificateAttributes,
		},
		"RenewCertificate": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/renew",
			HandlerFunc: c.RenewCertificate,
		},
		"RevokeCertificate": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/revoke",
			HandlerFunc: c.RevokeCertificate,
		},
		"ValidateIssueCertificateAttributes": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes/validate",
			HandlerFunc: c.ValidateIssueCertificateAttributes,
		},
		"ValidateRevokeCertificateAttributes": model.Route{
			Method:      strings.ToUpper("Post"),
			Pattern:     "/v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes/validate",
			HandlerFunc: c.ValidateRevokeCertificateAttributes,
		},
	}
}

// IdentifyCertificate - Identify Certificate
func (c *CertificateManagementAPIController) IdentifyCertificate(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	certificateIdentificationRequestDtoParam := model.CertificateIdentificationRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	certificateIdentificationRequestDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCertificateIdentificationRequestDtoRequired(certificateIdentificationRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCertificateIdentificationRequestDtoConstraints(certificateIdentificationRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.IdentifyCertificate(r.Context(), uuidParam, certificateIdentificationRequestDtoParam)
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

// IssueCertificate - Issue Certificate
func (c *CertificateManagementAPIController) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	certificateSignRequestDtoParam := model.CertificateSignRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	certificateSignRequestDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCertificateSignRequestDtoRequired(certificateSignRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCertificateSignRequestDtoConstraints(certificateSignRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.IssueCertificate(r.Context(), uuidParam, certificateSignRequestDtoParam)
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

// ListIssueCertificateAttributes - List of Attributes to issue Certificate
func (c *CertificateManagementAPIController) ListIssueCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.ListIssueCertificateAttributes(r.Context(), uuidParam)
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

// ListRevokeCertificateAttributes - List of Attributes to revoke Certificate
func (c *CertificateManagementAPIController) ListRevokeCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	result, err := c.service.ListRevokeCertificateAttributes(r.Context(), uuidParam)
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

// RenewCertificate - Renew Certificate
func (c *CertificateManagementAPIController) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	certificateRenewRequestDtoParam := model.CertificateRenewRequestDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	certificateRenewRequestDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCertificateRenewRequestDtoRequired(certificateRenewRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCertificateRenewRequestDtoConstraints(certificateRenewRequestDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.RenewCertificate(r.Context(), uuidParam, certificateRenewRequestDtoParam)
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

// RevokeCertificate - Revoke Certificate
func (c *CertificateManagementAPIController) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	certRevocationDtoParam := model.CertRevocationDto{}
	jsonContent, err := io.ReadAll(r.Body)
	if err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}

	certRevocationDtoParam.Unmarshal(jsonContent)
	if err := model.AssertCertRevocationDtoRequired(certRevocationDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := model.AssertCertRevocationDtoConstraints(certRevocationDtoParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.RevokeCertificate(r.Context(), uuidParam, certRevocationDtoParam)
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

// ValidateIssueCertificateAttributes - Validate list of Attributes to issue Certificate
func (c *CertificateManagementAPIController) ValidateIssueCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	var requestAttributeDtoParam []model.RequestAttributeDto
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&requestAttributeDtoParam); err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}
	for _, el := range requestAttributeDtoParam {
		if err := model.AssertRequestAttributeDtoRequired(el); err != nil {
			c.errorHandler(w, r, err, nil)
			return
		}
	}
	result, err := c.service.ValidateIssueCertificateAttributes(r.Context(), uuidParam, requestAttributeDtoParam)
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

// ValidateRevokeCertificateAttributes - Validate list of Attributes to revoke certificate
func (c *CertificateManagementAPIController) ValidateRevokeCertificateAttributes(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	uuidParam := params["uuid"]
	if uuidParam == "" {
		c.errorHandler(w, r, &model.RequiredError{Field: "uuid"}, nil)
		return
	}
	var requestAttributeDtoParam []model.RequestAttributeDto
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&requestAttributeDtoParam); err != nil {
		c.errorHandler(w, r, &model.ParsingError{Err: err}, nil)
		return
	}
	for _, el := range requestAttributeDtoParam {
		if err := model.AssertRequestAttributeDtoRequired(el); err != nil {
			c.errorHandler(w, r, err, nil)
			return
		}
	}
	result, err := c.service.ValidateRevokeCertificateAttributes(r.Context(), uuidParam, requestAttributeDtoParam)
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
