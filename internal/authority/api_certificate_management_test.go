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

func TestRequireUUIDParam(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = mux.SetURLVars(req, map[string]string{"uuid": "authority-uuid"})
		rec := httptest.NewRecorder()
		called := false
		errorHandler := func(http.ResponseWriter, *http.Request, error, *model.ImplResponse) {
			called = true
		}

		got, ok := requireUUIDParam(rec, req, errorHandler)

		if !ok {
			t.Fatal("expected ok = true")
		}
		if got != "authority-uuid" {
			t.Errorf("uuid = %q, want %q", got, "authority-uuid")
		}
		if called {
			t.Error("errorHandler should not have been called")
		}
	})

	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		var gotErr error
		errorHandler := func(_ http.ResponseWriter, _ *http.Request, err error, _ *model.ImplResponse) {
			gotErr = err
		}

		got, ok := requireUUIDParam(rec, req, errorHandler)

		if ok {
			t.Fatal("expected ok = false")
		}
		if got != "" {
			t.Errorf("uuid = %q, want empty", got)
		}
		requiredErr, isRequired := gotErr.(*model.RequiredError)
		if !isRequired {
			t.Fatalf("errorHandler err type = %T, want *model.RequiredError", gotErr)
		}
		if requiredErr.Field != "uuid" {
			t.Errorf("field = %q, want %q", requiredErr.Field, "uuid")
		}
	})
}

// recordedCertificateCall captures one invocation of a fake CertificateManagementAPIServicer
// method, so tests can assert which method the controller delegated to and with what
// arguments, without needing Vault or a database.
type recordedCertificateCall struct {
	method string
	uuid   string
	body   any
}

// fakeCertificateManagementAPIServicer implements CertificateManagementAPIServicer (already
// an interface in api.go) purely in memory, so CertificateManagementAPIController can be
// exercised directly.
type fakeCertificateManagementAPIServicer struct {
	calls []recordedCertificateCall
	resp  model.ImplResponse
	err   error
}

var _ CertificateManagementAPIServicer = (*fakeCertificateManagementAPIServicer)(nil)

func (f *fakeCertificateManagementAPIServicer) record(method, uuid string, body any) (model.ImplResponse, error) {
	f.calls = append(f.calls, recordedCertificateCall{method: method, uuid: uuid, body: body})
	return f.resp, f.err
}

func (f *fakeCertificateManagementAPIServicer) IdentifyCertificate(_ context.Context, uuid string, dto model.CertificateIdentificationRequestDto) (model.ImplResponse, error) {
	return f.record("IdentifyCertificate", uuid, dto)
}

func (f *fakeCertificateManagementAPIServicer) IssueCertificate(_ context.Context, uuid string, dto model.CertificateSignRequestDto) (model.ImplResponse, error) {
	return f.record("IssueCertificate", uuid, dto)
}

func (f *fakeCertificateManagementAPIServicer) ListIssueCertificateAttributes(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("ListIssueCertificateAttributes", uuid, nil)
}

func (f *fakeCertificateManagementAPIServicer) ListRevokeCertificateAttributes(_ context.Context, uuid string) (model.ImplResponse, error) {
	return f.record("ListRevokeCertificateAttributes", uuid, nil)
}

func (f *fakeCertificateManagementAPIServicer) RenewCertificate(_ context.Context, uuid string, dto model.CertificateRenewRequestDto) (model.ImplResponse, error) {
	return f.record("RenewCertificate", uuid, dto)
}

func (f *fakeCertificateManagementAPIServicer) RevokeCertificate(_ context.Context, uuid string, dto model.CertRevocationDto) (model.ImplResponse, error) {
	return f.record("RevokeCertificate", uuid, dto)
}

func (f *fakeCertificateManagementAPIServicer) ValidateIssueCertificateAttributes(_ context.Context, uuid string, attrs []model.RequestAttributeDto) (model.ImplResponse, error) {
	return f.record("ValidateIssueCertificateAttributes", uuid, attrs)
}

func (f *fakeCertificateManagementAPIServicer) ValidateRevokeCertificateAttributes(_ context.Context, uuid string, attrs []model.RequestAttributeDto) (model.ImplResponse, error) {
	return f.record("ValidateRevokeCertificateAttributes", uuid, attrs)
}

// errReader is an io.Reader whose Read always fails, simulating a request body that breaks
// while being streamed (as opposed to a body that is present but syntactically invalid).
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// allCertificateManagementRoutes lists every route CertificateManagementAPIController
// registers, keyed the same way as model.Routes.
var allCertificateManagementRoutes = []string{
	"IdentifyCertificate",
	"IssueCertificate",
	"ListIssueCertificateAttributes",
	"ListRevokeCertificateAttributes",
	"RenewCertificate",
	"RevokeCertificate",
	"ValidateIssueCertificateAttributes",
	"ValidateRevokeCertificateAttributes",
}

// certificateManagementRoutesWithBody is the subset of routes above whose handlers read
// r.Body before calling the service.
var certificateManagementRoutesWithBody = []string{
	"IdentifyCertificate",
	"IssueCertificate",
	"RenewCertificate",
	"RevokeCertificate",
	"ValidateIssueCertificateAttributes",
	"ValidateRevokeCertificateAttributes",
}

// decodeErrorMessage decodes a DefaultErrorHandler JSON response body, which is always a
// bare JSON string containing the error message.
func decodeErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var msg string
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode error response %q: %v", rec.Body.String(), err)
	}
	return msg
}

func newCertificateRequest(method, uuid string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, "/", body)
	if uuid != "" {
		req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	}
	return req
}

func TestCertificateManagementController_RoutesTable(t *testing.T) {
	want := map[string]struct {
		method  string
		pattern string
	}{
		"IdentifyCertificate":                 {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/identify"},
		"IssueCertificate":                    {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/issue"},
		"ListIssueCertificateAttributes":      {http.MethodGet, "/v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes"},
		"ListRevokeCertificateAttributes":     {http.MethodGet, "/v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes"},
		"RenewCertificate":                    {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/renew"},
		"RevokeCertificate":                   {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/revoke"},
		"ValidateIssueCertificateAttributes":  {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes/validate"},
		"ValidateRevokeCertificateAttributes": {http.MethodPost, "/v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes/validate"},
	}

	routes := NewCertificateManagementAPIController(&fakeCertificateManagementAPIServicer{}).Routes()

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

func TestNewCertificateManagementAPIController_DefaultsToDefaultErrorHandler(t *testing.T) {
	fake := &fakeCertificateManagementAPIServicer{}
	controller := NewCertificateManagementAPIController(fake)
	rec := httptest.NewRecorder()
	req := newCertificateRequest(http.MethodGet, "", nil)

	controller.Routes()["ListIssueCertificateAttributes"].HandlerFunc(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d (model.DefaultErrorHandler on a RequiredError)", rec.Code, http.StatusUnprocessableEntity)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("service should not have been called, got %+v", fake.calls)
	}
}

func TestWithCertificateManagementAPIErrorHandler_OverridesDefault(t *testing.T) {
	var gotErr error
	custom := func(w http.ResponseWriter, _ *http.Request, err error, _ *model.ImplResponse) {
		gotErr = err
		w.WriteHeader(http.StatusTeapot)
	}
	fake := &fakeCertificateManagementAPIServicer{}
	controller := NewCertificateManagementAPIController(fake, WithCertificateManagementAPIErrorHandler(custom))
	rec := httptest.NewRecorder()
	req := newCertificateRequest(http.MethodGet, "", nil)

	controller.Routes()["ListIssueCertificateAttributes"].HandlerFunc(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d (custom error handler should have run instead of the default)", rec.Code, http.StatusTeapot)
	}
	if _, ok := gotErr.(*model.RequiredError); !ok {
		t.Fatalf("err type = %T, want *model.RequiredError", gotErr)
	}
}

func TestCertificateManagementHandlers_MissingUUIDRejectsBeforeReachingService(t *testing.T) {
	for _, route := range allCertificateManagementRoutes {
		t.Run(route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newCertificateRequest(http.MethodPost, "", nil)

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

func TestCertificateManagementBodyHandlers_UnreadableBodyRejectsBeforeReachingService(t *testing.T) {
	for _, route := range certificateManagementRoutesWithBody {
		t.Run(route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newCertificateRequest(http.MethodPost, "authority-uuid", errReader{err: errors.New("connection reset")})

			controller.Routes()[route].HandlerFunc(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d (model.DefaultErrorHandler on a ParsingError)", rec.Code, http.StatusBadRequest)
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

func TestValidateCertificateAttributesHandlers_MalformedBodyRejectsBeforeReachingService(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantSubstring string
	}{
		{
			name:          "invalid JSON syntax",
			body:          `[{"name": "x",]`,
			wantSubstring: "invalid character",
		},
		{
			name:          "unknown field",
			body:          `[{"bogus":"x","name":"n","content":[]}]`,
			wantSubstring: "unknown field",
		},
	}
	routes := []string{"ValidateIssueCertificateAttributes", "ValidateRevokeCertificateAttributes"}

	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				fake := &fakeCertificateManagementAPIServicer{}
				controller := NewCertificateManagementAPIController(fake)
				rec := httptest.NewRecorder()
				req := newCertificateRequest(http.MethodPost, "authority-uuid", strings.NewReader(tc.body))

				controller.Routes()[route].HandlerFunc(rec, req)

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
				}
				if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, tc.wantSubstring) {
					t.Errorf("message = %q, want substring %q", msg, tc.wantSubstring)
				}
				if len(fake.calls) != 0 {
					t.Errorf("service should not have been called, got %+v", fake.calls)
				}
			})
		}
	}
}

func TestGjsonBodyCertificateHandlers_RejectsWhenTopLevelRequiredFieldMissing(t *testing.T) {
	// Each body is well-formed JSON that is missing exactly one required field, so the
	// resulting RequiredError is deterministic (AssertXxxRequired iterates a map, so a body
	// missing more than one field at once would make the reported field nondeterministic).
	cases := []struct {
		route     string
		body      string
		wantField string
	}{
		{
			route:     "IdentifyCertificate",
			body:      `{"certificate":"YWJj"}`,
			wantField: "raProfileAttributes",
		},
		{
			route:     "IssueCertificate",
			body:      `{"format":"pkcs10","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			wantField: "request",
		},
		{
			route:     "RenewCertificate",
			body:      `{"request":"cmVx","format":"pkcs10","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			wantField: "certificate",
		},
		{
			route:     "RevokeCertificate",
			body:      `{"reason":"unspecified","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			wantField: "certificate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newCertificateRequest(http.MethodPost, "authority-uuid", strings.NewReader(tc.body))

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

func TestValidateCertificateAttributesHandlers_RejectsElementMissingContent(t *testing.T) {
	routes := []string{"ValidateIssueCertificateAttributes", "ValidateRevokeCertificateAttributes"}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			req := newCertificateRequest(http.MethodPost, "authority-uuid", strings.NewReader(`[{"name":"x"}]`))

			controller.Routes()[route].HandlerFunc(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
			}
			if msg := decodeErrorMessage(t, rec); !strings.Contains(msg, "content") {
				t.Errorf("message = %q, want it to mention field %q", msg, "content")
			}
			if len(fake.calls) != 0 {
				t.Errorf("service should not have been called, got %+v", fake.calls)
			}
		})
	}
}

func TestCertificateManagementHandlers_DelegateToServiceAndEncodeResponse(t *testing.T) {
	cases := []struct {
		route     string
		method    string
		body      string
		checkBody func(t *testing.T, body any)
	}{
		{
			route:  "IdentifyCertificate",
			method: http.MethodPost,
			body:   `{"certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			checkBody: func(t *testing.T, body any) {
				dto, ok := body.(model.CertificateIdentificationRequestDto)
				if !ok {
					t.Fatalf("body type = %T, want model.CertificateIdentificationRequestDto", body)
				}
				if dto.Certificate != "YWJj" {
					t.Errorf("certificate = %q, want %q", dto.Certificate, "YWJj")
				}
			},
		},
		{
			route:  "IssueCertificate",
			method: http.MethodPost,
			body:   `{"request":"cmVx","format":"pkcs10","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			checkBody: func(t *testing.T, body any) {
				dto, ok := body.(model.CertificateSignRequestDto)
				if !ok {
					t.Fatalf("body type = %T, want model.CertificateSignRequestDto", body)
				}
				if dto.Request != "cmVx" || dto.CertificateRequestFormat != model.CERTIFICATEREQUESTFORMAT_PKCS10 {
					t.Errorf("dto = %+v, unexpected", dto)
				}
			},
		},
		{
			route:  "ListIssueCertificateAttributes",
			method: http.MethodGet,
			checkBody: func(t *testing.T, body any) {
				if body != nil {
					t.Errorf("body = %v, want nil (this handler takes no request body)", body)
				}
			},
		},
		{
			route:  "ListRevokeCertificateAttributes",
			method: http.MethodGet,
			checkBody: func(t *testing.T, body any) {
				if body != nil {
					t.Errorf("body = %v, want nil (this handler takes no request body)", body)
				}
			},
		},
		{
			route:  "RenewCertificate",
			method: http.MethodPost,
			body:   `{"request":"cmVx","format":"pkcs10","certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			checkBody: func(t *testing.T, body any) {
				dto, ok := body.(model.CertificateRenewRequestDto)
				if !ok {
					t.Fatalf("body type = %T, want model.CertificateRenewRequestDto", body)
				}
				if dto.Certificate != "YWJj" {
					t.Errorf("certificate = %q, want %q", dto.Certificate, "YWJj")
				}
			},
		},
		{
			route:  "RevokeCertificate",
			method: http.MethodPost,
			body:   `{"reason":"unspecified","certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`,
			checkBody: func(t *testing.T, body any) {
				dto, ok := body.(model.CertRevocationDto)
				if !ok {
					t.Fatalf("body type = %T, want model.CertRevocationDto", body)
				}
				if dto.Reason != model.UNSPECIFIED || dto.Certificate != "YWJj" {
					t.Errorf("dto = %+v, unexpected", dto)
				}
			},
		},
		{
			route:  "ValidateIssueCertificateAttributes",
			method: http.MethodPost,
			body:   `[]`,
			checkBody: func(t *testing.T, body any) {
				attrs, ok := body.([]model.RequestAttributeDto)
				if !ok {
					t.Fatalf("body type = %T, want []model.RequestAttributeDto", body)
				}
				if len(attrs) != 0 {
					t.Errorf("attrs = %+v, want empty", attrs)
				}
			},
		},
		{
			route:  "ValidateRevokeCertificateAttributes",
			method: http.MethodPost,
			body:   `[]`,
			checkBody: func(t *testing.T, body any) {
				attrs, ok := body.([]model.RequestAttributeDto)
				if !ok {
					t.Fatalf("body type = %T, want []model.RequestAttributeDto", body)
				}
				if len(attrs) != 0 {
					t.Errorf("attrs = %+v, want empty", attrs)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{
				resp: model.ImplResponse{Code: http.StatusOK, Body: map[string]string{"marker": tc.route}},
			}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newCertificateRequest(tc.method, "authority-uuid", body)

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
			if call.uuid != "authority-uuid" {
				t.Errorf("uuid passed to service = %q, want %q", call.uuid, "authority-uuid")
			}
			tc.checkBody(t, call.body)
		})
	}
}

func TestCertificateManagementHandlers_PropagateServiceErrorAsHTTPResponse(t *testing.T) {
	cases := []struct {
		route  string
		method string
		body   string
	}{
		{"IdentifyCertificate", http.MethodPost, `{"certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`},
		{"IssueCertificate", http.MethodPost, `{"request":"cmVx","format":"pkcs10","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`},
		{"ListIssueCertificateAttributes", http.MethodGet, ""},
		{"ListRevokeCertificateAttributes", http.MethodGet, ""},
		{"RenewCertificate", http.MethodPost, `{"request":"cmVx","format":"pkcs10","certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`},
		{"RevokeCertificate", http.MethodPost, `{"reason":"unspecified","certificate":"YWJj","raProfileAttributes":[{"name":"ra_profile_engine","content":[{}]}]}`},
		{"ValidateIssueCertificateAttributes", http.MethodPost, `[]`},
		{"ValidateRevokeCertificateAttributes", http.MethodPost, `[]`},
	}

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			fake := &fakeCertificateManagementAPIServicer{
				resp: model.ImplResponse{Code: http.StatusBadGateway},
				err:  errors.New("vault unavailable"),
			}
			controller := NewCertificateManagementAPIController(fake)
			rec := httptest.NewRecorder()
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := newCertificateRequest(tc.method, "authority-uuid", body)

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
