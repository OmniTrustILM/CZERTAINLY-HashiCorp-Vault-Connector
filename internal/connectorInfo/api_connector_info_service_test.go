package connectorInfo

import (
	"context"
	"net/http"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
)

func testRoutes() []model.InfoResponse {
	return []model.InfoResponse{{
		FunctionGroupCode: model.DISCOVERY_PROVIDER,
		Kinds:             []string{"HashiCorp-Vault"},
		EndPoints: []model.EndpointDto{{
			Uuid:     "b241a1a3-2f8a-4d2c-9a0b-1f0f9c2d4e5f",
			Name:     "listSupportedFunctions",
			Context:  "/v1",
			Method:   http.MethodGet,
			Required: true,
		}},
	}}
}

func TestListSupportedFunctionsReturnsConfiguredRoutes(t *testing.T) {
	resp, err := NewConnectorInfoAPIService(testRoutes()).ListSupportedFunctions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code != http.StatusOK {
		t.Errorf("code: got %d, want %d", resp.Code, http.StatusOK)
	}
	body, ok := resp.Body.([]model.InfoResponse)
	if !ok {
		t.Fatalf("body: got %T, want []model.InfoResponse", resp.Body)
	}
	if len(body) != 1 {
		t.Fatalf("got %d info responses, want 1", len(body))
	}
	if body[0].FunctionGroupCode != model.DISCOVERY_PROVIDER {
		t.Errorf("function group: got %q, want %q", body[0].FunctionGroupCode, model.DISCOVERY_PROVIDER)
	}
}

func TestListSupportedFunctionsReturnsEmptyWhenNoRoutesConfigured(t *testing.T) {
	resp, err := NewConnectorInfoAPIService(nil).ListSupportedFunctions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body, ok := resp.Body.([]model.InfoResponse)
	if !ok {
		t.Fatalf("body: got %T, want []model.InfoResponse", resp.Body)
	}
	if len(body) != 0 {
		t.Fatalf("got %d info responses, want 0", len(body))
	}
}

func TestServiceReturnsTheRoutesItWasConstructedWith(t *testing.T) {
	routes := testRoutes()
	resp, _ := NewConnectorInfoAPIService(routes).ListSupportedFunctions(context.Background())

	body := resp.Body.([]model.InfoResponse)
	if body[0].EndPoints[0].Name != routes[0].EndPoints[0].Name {
		t.Errorf("endpoint name: got %q, want %q", body[0].EndPoints[0].Name, routes[0].EndPoints[0].Name)
	}
}
