package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
)

func TestCheckHealthReportsOK(t *testing.T) {
	resp, err := NewHealthCheckAPIService().CheckHealth(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusOK {
		t.Errorf("code: got %d, want %d", resp.Code, http.StatusOK)
	}
	body, ok := resp.Body.(model.HealthDto)
	if !ok {
		t.Fatalf("body: got %T, want model.HealthDto", resp.Body)
	}
	if body.Status != model.OK {
		t.Errorf("status: got %q, want %q", body.Status, model.OK)
	}
}

func TestRoutesExposeHealthEndpoint(t *testing.T) {
	routes := NewHealthCheckAPIController(NewHealthCheckAPIService()).Routes()

	route, ok := routes["CheckHealth"]
	if !ok {
		t.Fatal(`no route registered under "CheckHealth"`)
	}
	if route.Method != http.MethodGet {
		t.Errorf("method: got %q, want %q", route.Method, http.MethodGet)
	}
	if route.Pattern != "/v1/health" {
		t.Errorf("pattern: got %q, want %q", route.Pattern, "/v1/health")
	}
}

func TestCheckHealthHandlerWritesOKJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)

	controller := NewHealthCheckAPIController(NewHealthCheckAPIService())
	controller.Routes()["CheckHealth"].HandlerFunc(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	var body model.HealthDto
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != model.OK {
		t.Errorf("status: got %q, want %q", body.Status, model.OK)
	}
}
