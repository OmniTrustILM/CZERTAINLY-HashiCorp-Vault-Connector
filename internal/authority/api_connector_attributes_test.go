package authority

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/gorilla/mux"
)

// recordedConnectorCall captures one invocation of a fake
// ConnectorAttributesAPIServicer method.
type recordedConnectorCall struct {
	method string
	param  string
	body   any
}

// fakeConnectorAttributesAPIServicer implements ConnectorAttributesAPIServicer
// (already an interface in api.go) purely in memory, so
// ConnectorAttributesAPIController can be exercised directly.
type fakeConnectorAttributesAPIServicer struct {
	calls []recordedConnectorCall
	resp  model.ImplResponse
	err   error
}

var _ ConnectorAttributesAPIServicer = (*fakeConnectorAttributesAPIServicer)(nil)

func (f *fakeConnectorAttributesAPIServicer) record(method, param string, body any) (model.ImplResponse, error) {
	f.calls = append(f.calls, recordedConnectorCall{method: method, param: param, body: body})
	return f.resp, f.err
}

func (f *fakeConnectorAttributesAPIServicer) ListAttributeDefinitions(_ context.Context, kind string) (model.ImplResponse, error) {
	return f.record("ListAttributeDefinitions", kind, nil)
}

func (f *fakeConnectorAttributesAPIServicer) CredentialAttributesCallback(_ context.Context, credentialType string) (model.ImplResponse, error) {
	return f.record("CredentialAttributesCallback", credentialType, nil)
}

func (f *fakeConnectorAttributesAPIServicer) ValidateAttributes(_ context.Context, kind string, attributes []model.Attribute) (model.ImplResponse, error) {
	return f.record("ValidateAttributes", kind, attributes)
}

func TestConnectorAttributesController_RoutesTable(t *testing.T) {
	want := map[string]struct {
		method  string
		pattern string
	}{
		"ListAttributeDefinitions": {http.MethodGet, "/v1/authorityProvider/{kind}/attributes"},
		"Callback":                 {http.MethodGet, "/v1/authorityProvider/credentialType/{credentialType}/callback"},
		"ValidateAttributes":       {http.MethodPost, "/v1/authorityProvider/{kind}/attributes/validate"},
	}

	routes := NewConnectorAttributesAPIController(&fakeConnectorAttributesAPIServicer{}).Routes()

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

func TestNewConnectorAttributesAPIController_WithErrorHandlerOverridesDefault(t *testing.T) {
	var gotErr error
	custom := func(w http.ResponseWriter, _ *http.Request, err error, _ *model.ImplResponse) {
		gotErr = err
		w.WriteHeader(http.StatusTeapot)
	}
	fake := &fakeConnectorAttributesAPIServicer{}
	controller := NewConnectorAttributesAPIController(fake, WithConnectorAttributesAPIErrorHandler(custom))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	controller.Routes()["ListAttributeDefinitions"].HandlerFunc(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d (custom error handler should have run)", rec.Code, http.StatusTeapot)
	}
	if _, ok := gotErr.(*model.RequiredError); !ok {
		t.Fatalf("err type = %T, want *model.RequiredError", gotErr)
	}
	if len(fake.calls) != 0 {
		t.Errorf("service should not have been called, got %+v", fake.calls)
	}
}

func TestConnectorAttributesHandlers_MissingPathParamRejectsBeforeReachingService(t *testing.T) {
	tests := []struct {
		route     string
		wantField string
	}{
		{route: "ListAttributeDefinitions", wantField: "kind"},
		{route: "Callback", wantField: "credentialType"},
		{route: "ValidateAttributes", wantField: "kind"},
	}

	for _, tc := range tests {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeConnectorAttributesAPIServicer{}
			controller := NewConnectorAttributesAPIController(fake)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			controller.Routes()[tc.route].HandlerFunc(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
			}
			if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, tc.wantField) {
				t.Errorf("message = %q, want it to mention %q", msg, tc.wantField)
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

func TestValidateAttributesHandler_UnreadableBodyRejectsBeforeReachingService(t *testing.T) {
	fake := &fakeConnectorAttributesAPIServicer{}
	controller := NewConnectorAttributesAPIController(fake)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", errReader{err: errors.New("connection reset")})
	req = mux.SetURLVars(req, map[string]string{"kind": model.CONNECTOR_KIND})

	controller.Routes()["ValidateAttributes"].HandlerFunc(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if len(fake.calls) != 0 {
		t.Errorf("service should not have been called, got %+v", fake.calls)
	}
}

func TestConnectorAttributesHandlers_DelegateToServiceAndEncodeResponse(t *testing.T) {
	tests := []struct {
		route  string
		method string
		vars   map[string]string
		body   string
	}{
		{route: "ListAttributeDefinitions", method: http.MethodGet, vars: map[string]string{"kind": model.CONNECTOR_KIND}},
		{route: "Callback", method: http.MethodGet, vars: map[string]string{"credentialType": model.APPROLE_CRED}},
		{route: "ValidateAttributes", method: http.MethodPost, vars: map[string]string{"kind": model.CONNECTOR_KIND}, body: "{}"},
	}

	for _, tc := range tests {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeConnectorAttributesAPIServicer{
				resp: model.ImplResponse{Code: http.StatusOK, Body: map[string]string{"marker": tc.route}},
			}
			controller := NewConnectorAttributesAPIController(fake)
			rec := httptest.NewRecorder()
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			var req *http.Request
			if body != nil {
				req = httptest.NewRequest(tc.method, "/", body)
			} else {
				req = httptest.NewRequest(tc.method, "/", nil)
			}
			req = mux.SetURLVars(req, tc.vars)

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
		})
	}
}

func TestConnectorAttributesHandlers_PropagateServiceErrorAsHTTPResponse(t *testing.T) {
	tests := []struct {
		route  string
		method string
		vars   map[string]string
		body   string
	}{
		{route: "ListAttributeDefinitions", method: http.MethodGet, vars: map[string]string{"kind": model.CONNECTOR_KIND}},
		{route: "Callback", method: http.MethodGet, vars: map[string]string{"credentialType": model.APPROLE_CRED}},
		{route: "ValidateAttributes", method: http.MethodPost, vars: map[string]string{"kind": model.CONNECTOR_KIND}, body: "{}"},
	}

	for _, tc := range tests {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeConnectorAttributesAPIServicer{
				resp: model.ImplResponse{Code: http.StatusBadGateway},
				err:  errors.New("vault unavailable"),
			}
			controller := NewConnectorAttributesAPIController(fake)
			rec := httptest.NewRecorder()
			var req *http.Request
			if tc.body != "" {
				req = httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
			} else {
				req = httptest.NewRequest(tc.method, "/", nil)
			}
			req = mux.SetURLVars(req, tc.vars)

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
