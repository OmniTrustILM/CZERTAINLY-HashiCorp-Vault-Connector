package authority

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/gorilla/mux"
)

// recordedAuthorityCall captures one invocation of a fake AuthorityManagementAPIServicer
// method, so tests can assert which method the controller delegated to and with what
// arguments, without needing Vault or a database.
type recordedAuthorityCall struct {
	method string
	uuid   string
	body   any
}

// fakeAuthorityManagementAPIServicer implements AuthorityManagementAPIServicer (already an
// interface in api.go) purely in memory, so AuthorityManagementAPIController can be
// exercised directly.
type fakeAuthorityManagementAPIServicer struct {
	calls []recordedAuthorityCall
	resp  model.ImplResponse
	err   error
}

var _ AuthorityManagementAPIServicer = (*fakeAuthorityManagementAPIServicer)(nil)

func (f *fakeAuthorityManagementAPIServicer) record(method, uuid string, body any) (model.ImplResponse, error) {
	f.calls = append(f.calls, recordedAuthorityCall{method: method, uuid: uuid, body: body})
	return f.resp, f.err
}

func (f *fakeAuthorityManagementAPIServicer) CreateAuthorityInstance(_ context.Context, dto model.AuthorityProviderInstanceRequestDto) (model.ImplResponse, error) {
	return f.record("CreateAuthorityInstance", "", dto)
}

func (f *fakeAuthorityManagementAPIServicer) GetAuthorityInstance(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("GetAuthorityInstance", uuid, nil)
}

func (f *fakeAuthorityManagementAPIServicer) GetCaCertificates(_ context.Context, uuid string, dto model.CaCertificatesRequestDto) (model.ImplResponse, error) {
	return f.record("GetCaCertificates", uuid, dto)
}

func (f *fakeAuthorityManagementAPIServicer) GetConnection(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("GetConnection", uuid, nil)
}

func (f *fakeAuthorityManagementAPIServicer) GetCrl(_ context.Context, uuid string, dto model.CertificateRevocationListRequestDto) (model.ImplResponse, error) {
	return f.record("GetCrl", uuid, dto)
}

func (f *fakeAuthorityManagementAPIServicer) ListAuthorityInstances(_ context.Context) (model.ImplResponse, error) {
	return f.record("ListAuthorityInstances", "", nil)
}

func (f *fakeAuthorityManagementAPIServicer) ListRAProfileAttributes(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("ListRAProfileAttributes", uuid, nil)
}

func (f *fakeAuthorityManagementAPIServicer) RemoveAuthorityInstance(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("RemoveAuthorityInstance", uuid, nil)
}

func (f *fakeAuthorityManagementAPIServicer) UpdateAuthorityInstance(_ context.Context, uuid string, dto model.AuthorityProviderInstanceRequestDto) (model.ImplResponse, error) {
	return f.record("UpdateAuthorityInstance", uuid, dto)
}

func (f *fakeAuthorityManagementAPIServicer) ValidateRAProfileAttributes(_ context.Context, uuid string, attrs []model.Attribute) (model.ImplResponse, error) {
	return f.record("ValidateRAProfileAttributes", uuid, attrs)
}

func (f *fakeAuthorityManagementAPIServicer) RAProfileCallback(_ context.Context, uuid string, engineName string) (model.ImplResponse, error) {
	return f.record("RAProfileCallback", uuid, engineName)
}

// newAuthorityRequest builds a request carrying the given uuid/engineName mux vars (either
// may be omitted by passing "") and an optional body.
func newAuthorityRequest(method, uuid, engineName string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, "/", body)
	vars := map[string]string{}
	if uuid != "" {
		vars["uuid"] = uuid
	}
	if engineName != "" {
		vars["engineName"] = engineName
	}
	if len(vars) > 0 {
		req = mux.SetURLVars(req, vars)
	}
	return req
}

func TestAuthorityManagementController_RoutesTable(t *testing.T) {
	want := map[string]struct {
		method  string
		pattern string
	}{
		"CreateAuthorityInstance":     {http.MethodPost, "/v1/authorityProvider/authorities"},
		"GetAuthorityInstance":        {http.MethodGet, "/v1/authorityProvider/authorities/{uuid}"},
		"GetCaCertificates":           {http.MethodPost, "/v1/authorityProvider/authorities/{uuid}/caCertificates"},
		"GetConnection":               {http.MethodGet, "/v1/authorityProvider/authorities/{uuid}/connect"},
		"GetCrl":                      {http.MethodPost, "/v1/authorityProvider/authorities/{uuid}/crl"},
		"ListAuthorityInstances":      {http.MethodGet, "/v1/authorityProvider/authorities"},
		"ListRAProfileAttributes":     {http.MethodGet, "/v1/authorityProvider/authorities/{uuid}/raProfile/attributes"},
		"RemoveAuthorityInstance":     {http.MethodDelete, "/v1/authorityProvider/authorities/{uuid}"},
		"UpdateAuthorityInstance":     {http.MethodPost, "/v1/authorityProvider/authorities/{uuid}"},
		"ValidateRAProfileAttributes": {http.MethodPost, "/v1/authorityProvider/authorities/{uuid}/raProfile/attributes/validate"},
		"RAProfileCallback":           {http.MethodGet, "/v1/authorityProvider/authorities/{uuid}/raProfileRole/{engineName:.*}/callback"},
	}

	routes := NewAuthorityManagementAPIController(&fakeAuthorityManagementAPIServicer{}).Routes()

	if len(routes) != len(want) {
		t.Fatalf("route count = %d, want %d (routes=%v)", len(routes), len(want), routes)
	}
	for name, w := range want {
		route, ok := routes[name]
		if !ok {
			t.Errorf("missing route %q", name)
			continue
		}
		if route.Method != w.method {
			t.Errorf("%s: method = %q, want %q", name, route.Method, w.method)
		}
		if route.Pattern != w.pattern {
			t.Errorf("%s: pattern = %q, want %q", name, route.Pattern, w.pattern)
		}
		if route.HandlerFunc == nil {
			t.Errorf("%s: HandlerFunc is nil", name)
		}
	}
}

func TestNewAuthorityManagementAPIController_DefaultsToDefaultErrorHandler(t *testing.T) {
	fake := &fakeAuthorityManagementAPIServicer{}
	controller := NewAuthorityManagementAPIController(fake)
	rec := httptest.NewRecorder()
	req := newAuthorityRequest(http.MethodGet, "", "", nil)

	controller.Routes()["GetAuthorityInstance"].HandlerFunc(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d (model.DefaultErrorHandler on a RequiredError)", rec.Code, http.StatusUnprocessableEntity)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("service should not have been called, got %+v", fake.calls)
	}
}

func TestWithAuthorityManagementAPIErrorHandler_OverridesDefault(t *testing.T) {
	var gotErr error
	custom := func(w http.ResponseWriter, _ *http.Request, err error, _ *model.ImplResponse) {
		gotErr = err
		w.WriteHeader(http.StatusTeapot)
	}
	fake := &fakeAuthorityManagementAPIServicer{}
	controller := NewAuthorityManagementAPIController(fake, WithAuthorityManagementAPIErrorHandler(custom))
	rec := httptest.NewRecorder()
	req := newAuthorityRequest(http.MethodGet, "", "", nil)

	controller.Routes()["GetAuthorityInstance"].HandlerFunc(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d (custom error handler should have run instead of the default)", rec.Code, http.StatusTeapot)
	}
	if _, ok := gotErr.(*model.RequiredError); !ok {
		t.Fatalf("err type = %T, want *model.RequiredError", gotErr)
	}
}

// authorityRoutesRequiringUUID lists the handlers that check the uuid path parameter before
// doing anything else. CreateAuthorityInstance and ListAuthorityInstances have no uuid in
// their route and are exercised separately.
var authorityRoutesRequiringUUID = []string{
	"GetAuthorityInstance",
	"GetCaCertificates",
	"GetConnection",
	"GetCrl",
	"ListRAProfileAttributes",
	"RemoveAuthorityInstance",
	"UpdateAuthorityInstance",
	"ValidateRAProfileAttributes",
	"RAProfileCallback",
}

func TestAuthorityManagementHandlers_MissingUUIDRejectsBeforeReachingService(t *testing.T) {
	for _, route := range authorityRoutesRequiringUUID {
		t.Run(route, func(t *testing.T) {
			fake := &fakeAuthorityManagementAPIServicer{}
			controller := NewAuthorityManagementAPIController(fake)
			rec := httptest.NewRecorder()
			// engineName is present but uuid is not, proving the uuid check is what rejects
			// the request (RAProfileCallback also needs engineName; that failure path is
			// covered separately).
			req := newAuthorityRequest(http.MethodPost, "", "pki", nil)

			controller.Routes()[route].HandlerFunc(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
			}
			if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, "uuid") {
				t.Errorf("message = %q, want it to mention %q", msg, "uuid")
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

func TestRAProfileCallbackHandler_MissingEngineNameRejectsBeforeReachingService(t *testing.T) {
	fake := &fakeAuthorityManagementAPIServicer{}
	controller := NewAuthorityManagementAPIController(fake)
	rec := httptest.NewRecorder()
	req := newAuthorityRequest(http.MethodGet, "authority-uuid", "", nil)

	controller.Routes()["RAProfileCallback"].HandlerFunc(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, "engineName") {
		t.Errorf("message = %q, want it to mention %q", msg, "engineName")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("service should not have been called, got %+v", fake.calls)
	}
}

func TestAuthorityManagementBodyHandlers_UnreadableBodyRejectsBeforeReachingService(t *testing.T) {
	cases := []struct {
		route string
		uuid  string // "" for CreateAuthorityInstance, whose route has no uuid
	}{
		{"CreateAuthorityInstance", ""},
		{"GetCaCertificates", "authority-uuid"},
		{"GetCrl", "authority-uuid"},
		{"UpdateAuthorityInstance", "authority-uuid"},
		{"ValidateRAProfileAttributes", "authority-uuid"},
	}
	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeAuthorityManagementAPIServicer{}
			controller := NewAuthorityManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newAuthorityRequest(http.MethodPost, tc.uuid, "", errReader{err: errors.New("connection reset")})

			controller.Routes()[tc.route].HandlerFunc(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

func TestAuthorityManagementHandlers_RejectsWhenTopLevelRequiredFieldMissing(t *testing.T) {
	// Only CreateAuthorityInstance, GetCaCertificates and GetCrl assert their decoded body's
	// required fields; UpdateAuthorityInstance and ValidateRAProfileAttributes do not (see
	// bugfix_test.go).
	cases := []struct {
		route     string
		uuid      string
		body      string
		wantField string
	}{
		{
			route:     "CreateAuthorityInstance",
			body:      `{"name":"authority-1","attributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			wantField: "kind",
		},
		{
			route:     "GetCaCertificates",
			uuid:      "authority-uuid",
			body:      `{}`,
			wantField: "raProfileAttributes",
		},
		{
			route:     "GetCrl",
			uuid:      "authority-uuid",
			body:      `{}`,
			wantField: "raProfileAttributes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeAuthorityManagementAPIServicer{}
			controller := NewAuthorityManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newAuthorityRequest(http.MethodPost, tc.uuid, "", strings.NewReader(tc.body))

			controller.Routes()[tc.route].HandlerFunc(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
			}
			if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, tc.wantField) {
				t.Errorf("message = %q, want it to mention field %q", msg, tc.wantField)
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

// authorityHandlerCase describes a request that should reach the fake service for a given
// route, and how to verify what the service actually received.
type authorityHandlerCase struct {
	route      string
	method     string
	uuid       string
	engineName string
	body       string
	checkBody  func(t *testing.T, body any)
}

var authorityHandlerCases = []authorityHandlerCase{
	{
		route:  "CreateAuthorityInstance",
		method: http.MethodPost,
		body:   `{"name":"authority-1","kind":"PKI","attributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
		checkBody: func(t *testing.T, body any) {
			dto, ok := body.(model.AuthorityProviderInstanceRequestDto)
			if !ok {
				t.Fatalf("body type = %T, want model.AuthorityProviderInstanceRequestDto", body)
			}
			if dto.Name != "authority-1" || dto.Kind != "PKI" {
				t.Errorf("dto = %+v, unexpected", dto)
			}
		},
	},
	{
		route:  "GetAuthorityInstance",
		method: http.MethodGet,
		uuid:   "authority-uuid",
		checkBody: func(t *testing.T, body any) {
			if body != nil {
				t.Errorf("body = %v, want nil (this handler takes no request body)", body)
			}
		},
	},
	{
		route:  "GetCaCertificates",
		method: http.MethodPost,
		uuid:   "authority-uuid",
		body:   `{"raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
		checkBody: func(t *testing.T, body any) {
			dto, ok := body.(model.CaCertificatesRequestDto)
			if !ok {
				t.Fatalf("body type = %T, want model.CaCertificatesRequestDto", body)
			}
			if len(dto.RaProfileAttributes) != 1 {
				t.Errorf("raProfileAttributes = %+v, want 1 element", dto.RaProfileAttributes)
			}
		},
	},
	{
		route:  "GetConnection",
		method: http.MethodGet,
		uuid:   "authority-uuid",
		checkBody: func(t *testing.T, body any) {
			if body != nil {
				t.Errorf("body = %v, want nil (this handler takes no request body)", body)
			}
		},
	},
	{
		route:  "GetCrl",
		method: http.MethodPost,
		uuid:   "authority-uuid",
		body:   `{"delta":true,"raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
		checkBody: func(t *testing.T, body any) {
			dto, ok := body.(model.CertificateRevocationListRequestDto)
			if !ok {
				t.Fatalf("body type = %T, want model.CertificateRevocationListRequestDto", body)
			}
			if !dto.Delta {
				t.Errorf("delta = %v, want true", dto.Delta)
			}
		},
	},
	{
		route:  "ListAuthorityInstances",
		method: http.MethodGet,
		checkBody: func(t *testing.T, body any) {
			if body != nil {
				t.Errorf("body = %v, want nil (this handler takes no request body)", body)
			}
		},
	},
	{
		route:  "ListRAProfileAttributes",
		method: http.MethodGet,
		uuid:   "authority-uuid",
		checkBody: func(t *testing.T, body any) {
			if body != nil {
				t.Errorf("body = %v, want nil (this handler takes no request body)", body)
			}
		},
	},
	{
		route:  "RemoveAuthorityInstance",
		method: http.MethodDelete,
		uuid:   "authority-uuid",
		checkBody: func(t *testing.T, body any) {
			if body != nil {
				t.Errorf("body = %v, want nil (this handler takes no request body)", body)
			}
		},
	},
	{
		route:  "UpdateAuthorityInstance",
		method: http.MethodPost,
		uuid:   "authority-uuid",
		body:   `{"name":"authority-1","kind":"PKI","attributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
		checkBody: func(t *testing.T, body any) {
			dto, ok := body.(model.AuthorityProviderInstanceRequestDto)
			if !ok {
				t.Fatalf("body type = %T, want model.AuthorityProviderInstanceRequestDto", body)
			}
			if dto.Name != "authority-1" {
				t.Errorf("dto = %+v, unexpected", dto)
			}
		},
	},
	{
		route:  "ValidateRAProfileAttributes",
		method: http.MethodPost,
		uuid:   "authority-uuid",
		body:   `[{"name":"ra_profile_engine","content":[{"data":"team/pki"}]}]`,
		checkBody: func(t *testing.T, body any) {
			attrs, ok := body.([]model.Attribute)
			if !ok {
				t.Fatalf("body type = %T, want []model.Attribute", body)
			}
			if len(attrs) != 1 {
				t.Fatalf("attrs = %+v, want the one attribute from the request body", attrs)
			}
			if got := attrs[0].GetName(); got != "ra_profile_engine" {
				t.Errorf("name = %q, want %q", got, "ra_profile_engine")
			}
		},
	},
	{
		route:      "RAProfileCallback",
		method:     http.MethodGet,
		uuid:       "authority-uuid",
		engineName: "pki",
		checkBody: func(t *testing.T, body any) {
			engineName, ok := body.(string)
			if !ok || engineName != "pki" {
				t.Errorf("body = %v, want engineName %q", body, "pki")
			}
		},
	},
}

func TestAuthorityManagementHandlers_DelegateToServiceAndEncodeResponse(t *testing.T) {
	for _, tc := range authorityHandlerCases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeAuthorityManagementAPIServicer{
				resp: model.ImplResponse{Code: http.StatusOK, Body: map[string]string{"marker": tc.route}},
			}
			controller := NewAuthorityManagementAPIController(fake)
			rec := httptest.NewRecorder()
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newAuthorityRequest(tc.method, tc.uuid, tc.engineName, body)

			controller.Routes()[tc.route].HandlerFunc(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
			}
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response %q: %v", rec.Body.String(), err)
			}
			if got["marker"] != tc.route {
				t.Errorf("response marker = %q, want %q", got["marker"], tc.route)
			}
			if len(fake.calls) != 1 {
				t.Fatalf("service calls = %d, want 1: %+v", len(fake.calls), fake.calls)
			}
			call := fake.calls[0]
			if call.method != tc.route {
				t.Errorf("service method called = %q, want %q", call.method, tc.route)
			}
			if call.uuid != tc.uuid {
				t.Errorf("uuid passed to service = %q, want %q", call.uuid, tc.uuid)
			}
			tc.checkBody(t, call.body)
		})
	}
}

func TestAuthorityManagementHandlers_PropagateServiceErrorAsHTTPResponse(t *testing.T) {
	for _, tc := range authorityHandlerCases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeAuthorityManagementAPIServicer{
				resp: model.ImplResponse{Code: http.StatusBadGateway},
				err:  errors.New("vault unavailable"),
			}
			controller := NewAuthorityManagementAPIController(fake)
			rec := httptest.NewRecorder()
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newAuthorityRequest(tc.method, tc.uuid, tc.engineName, body)

			controller.Routes()[tc.route].HandlerFunc(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
			if msg := decodeErrorMessage(t, rec); msg != "vault unavailable" {
				t.Errorf("message = %q, want %q", msg, "vault unavailable")
			}
			if len(fake.calls) != 1 {
				t.Fatalf("service calls = %d, want 1: %+v", len(fake.calls), fake.calls)
			}
		})
	}
}
