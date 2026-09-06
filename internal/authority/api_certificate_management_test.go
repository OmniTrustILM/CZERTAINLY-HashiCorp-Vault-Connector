package authority

import (
	"net/http"
	"net/http/httptest"
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
