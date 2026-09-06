package secret

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sm "github.com/OmniTrustILM/hashicorp-vault-connector/internal/secret/model"
)

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problem {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content type: got %q, want %q", got, "application/problem+json")
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem document: %v", err)
	}
	return p
}

func TestProblemRenderersSetStatusTitleAndDetail(t *testing.T) {
	for _, tc := range []struct {
		name       string
		render     func(w http.ResponseWriter)
		wantStatus int
		wantTitle  string
	}{
		{"bad request", func(w http.ResponseWriter) { badrequest(w, "detail", sm.ATTRIBUTESERROR) },
			http.StatusBadRequest, "Bad request"},
		{"internal", func(w http.ResponseWriter) { internal(w, "detail") },
			http.StatusInternalServerError, "Internal server error"},
		{"unauthorized", func(w http.ResponseWriter) { unauthorized(w, "detail") },
			http.StatusUnauthorized, "Unauthorized"},
		{"forbidden", func(w http.ResponseWriter) { forbidden(w, "detail") },
			http.StatusForbidden, "Forbidden"},
		{"not found", func(w http.ResponseWriter) { notfound(w, "detail") },
			http.StatusNotFound, "Not found"},
		{"precondition", func(w http.ResponseWriter) { precondition(w, "detail", sm.RESOURCEALREADYEXISTS) },
			http.StatusPreconditionFailed, "Precondition failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.render(rec)

			if rec.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tc.wantStatus)
			}
			p := decodeProblem(t, rec)
			if p.Status != tc.wantStatus {
				t.Errorf("body status: got %d, want %d", p.Status, tc.wantStatus)
			}
			if p.Detail != "detail" {
				t.Errorf("detail: got %q, want %q", p.Detail, "detail")
			}
			if p.Type != problemJsonAboutBlankType {
				t.Errorf("type: got %q, want %q", p.Type, problemJsonAboutBlankType)
			}
			if p.Title != tc.wantTitle {
				t.Errorf("title: got %q, want %q", p.Title, tc.wantTitle)
			}
			if _, err := time.Parse(time.RFC3339, p.Timestamp); err != nil {
				t.Errorf("timestamp %q is not RFC3339: %v", p.Timestamp, err)
			}
		})
	}
}

func TestBadRequestIsRetryableAndInternalIsNot(t *testing.T) {
	rec := httptest.NewRecorder()
	badrequest(rec, "detail", sm.ATTRIBUTESERROR)
	if !decodeProblem(t, rec).Retryable {
		t.Error("bad request: got retryable false, want true")
	}

	rec = httptest.NewRecorder()
	internal(rec, "detail")
	if decodeProblem(t, rec).Retryable {
		t.Error("internal: got retryable true, want false")
	}
}
