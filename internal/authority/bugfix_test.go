package authority

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// A lookup that fails means the authority is not there, so the caller must be
// told that and not handed an unrelated marshalling message.
func TestAuthorityLookupFailureIsReportedAsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*AuthorityManagementAPIService) (model.ImplResponse, error)
	}{
		{"GetConnection", func(s *AuthorityManagementAPIService) (model.ImplResponse, error) {
			return s.GetConnection(t.Context(), "missing-uuid")
		}},
		{"UpdateAuthorityInstance", func(s *AuthorityManagementAPIService) (model.ImplResponse, error) {
			return s.UpdateAuthorityInstance(t.Context(), "missing-uuid", model.AuthorityProviderInstanceRequestDto{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeAuthorityRepository{findByUUIDErr: errors.New("no such row")}
			svc := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

			resp, err := tc.call(svc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Code != http.StatusNotFound {
				t.Errorf("status: got %d, want %d", resp.Code, http.StatusNotFound)
			}
			msg := resp.Body.(model.ErrorMessageDto).Message
			if msg != "Authority not found" {
				t.Errorf("message: got %q, want %q", msg, "Authority not found")
			}
		})
	}
}

// A repository failure must surface, not be reported as an empty list.
func TestListAuthorityInstancesReportsRepositoryFailure(t *testing.T) {
	repo := &fakeAuthorityRepository{listErr: errors.New("connection refused")}
	svc := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	resp, err := svc.ListAuthorityInstances(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", resp.Code, http.StatusInternalServerError)
	}
	if _, ok := resp.Body.(model.ErrorMessageDto); !ok {
		t.Errorf("body: got %T, want model.ErrorMessageDto", resp.Body)
	}
}

// The attributes in the request body must reach the service, not an empty slice.
func TestValidateRAProfileAttributesPassesTheRequestBodyThrough(t *testing.T) {
	fake := &fakeAuthorityManagementAPIServicer{resp: model.Response(http.StatusOK, nil)}
	controller := NewAuthorityManagementAPIController(fake)

	body := `[{"uuid":"a-uuid","name":"ra_profile_engine","content":[{"data":"team/pki"}]}]`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorityProvider/authorities/u1/raProfile/attributes/validate", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": "u1"})

	controller.Routes()["ValidateRAProfileAttributes"].HandlerFunc(rec, req)

	if len(fake.calls) != 1 {
		t.Fatalf("got %d service calls, want 1", len(fake.calls))
	}
	attrs, ok := fake.calls[0].body.([]model.Attribute)
	if !ok {
		t.Fatalf("body: got %T, want []model.Attribute", fake.calls[0].body)
	}
	if len(attrs) != 1 {
		t.Fatalf("got %d attributes through to the service, want 1", len(attrs))
	}
	if got := attrs[0].GetName(); got != "ra_profile_engine" {
		t.Errorf("name: got %q, want %q", got, "ra_profile_engine")
	}
}

// Update must reject an incomplete body the same way Create does.
func TestUpdateAuthorityInstanceRejectsAnIncompleteBody(t *testing.T) {
	fake := &fakeAuthorityManagementAPIServicer{resp: model.Response(http.StatusOK, nil)}
	controller := NewAuthorityManagementAPIController(fake)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/authorityProvider/authorities/u1", strings.NewReader(`{}`))
	req = mux.SetURLVars(req, map[string]string{"uuid": "u1"})

	controller.Routes()["UpdateAuthorityInstance"].HandlerFunc(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("an incomplete body was accepted with %d", rec.Code)
	}
	if len(fake.calls) != 0 {
		t.Errorf("the service was called %d times despite an invalid body", len(fake.calls))
	}
	if rec.Body.Len() == 0 {
		t.Error("the rejection carried no message for the caller")
	}
}
