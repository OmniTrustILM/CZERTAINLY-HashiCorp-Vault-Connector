package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"github.com/hashicorp/vault-client-go"
)

// newMountsServer starts a server answering the mount listing with body, under
// the given status.
func newMountsServer(t *testing.T, status int, body string) *vault.Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := vault.New(vault.WithAddress(server.URL))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	return client
}

const mountsResponse = `{"request_id":"stub","data":{"secret":{` +
	`"pki/":{"type":"pki","accessor":"pki_1234","running_plugin_version":"v1.2.3"},` +
	`"secret/":{"type":"kv","accessor":"kv_1234"}}}}`

func TestListPkiEnginesReturnsOnlyPkiMounts(t *testing.T) {
	client := newMountsServer(t, http.StatusOK, mountsResponse)

	engines, err := ListPkiEngines(context.Background(), client)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(engines) != 1 {
		t.Fatalf("engines: got %d, want 1", len(engines))
	}
	content, ok := engines[0].(model.ObjectAttributeContent)
	if !ok {
		t.Fatalf("content type: got %T, want model.ObjectAttributeContent", engines[0])
	}
	if content.Reference != "pki" {
		t.Errorf("reference: got %q, want %q", content.Reference, "pki")
	}
	data := content.Data
	if data["engineName"] != "pki" {
		t.Errorf("engineName: got %v, want %q", data["engineName"], "pki")
	}
	if data["engineAccesor"] != "pki_1234" {
		t.Errorf("engineAccesor: got %v, want %q", data["engineAccesor"], "pki_1234")
	}
	if data["runningPluginVersion"] != "v1.2.3" {
		t.Errorf("runningPluginVersion: got %v, want %q", data["runningPluginVersion"], "v1.2.3")
	}
}

func TestListPkiEnginesReportsARefusedListing(t *testing.T) {
	client := newMountsServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)

	engines, err := ListPkiEngines(context.Background(), client)

	if err == nil {
		t.Fatal("expected an error")
	}
	if engines != nil {
		t.Errorf("engines: got %v, want nil", engines)
	}
}

func TestListPkiEngineNamesReturnsTheEngineNames(t *testing.T) {
	client := newMountsServer(t, http.StatusOK, mountsResponse)

	names, err := ListPkiEngineNames(context.Background(), client)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "pki" {
		t.Errorf("names: got %v, want [pki]", names)
	}
}

func TestListPkiEngineNamesReportsARefusedListing(t *testing.T) {
	client := newMountsServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)

	if _, err := ListPkiEngineNames(context.Background(), client); err == nil {
		t.Fatal("expected an error")
	}
}
