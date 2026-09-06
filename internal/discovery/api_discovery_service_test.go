package discovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"go.uber.org/zap"
)

// fakeDiscoveryRepository is an in-memory stand-in for *db.DiscoveryRepository.
// Methods a test does not configure report that they were not expected.
type fakeDiscoveryRepository struct {
	findDiscovery *db.Discovery

	updateCalls []db.Discovery
	updateErr   error
}

func (f *fakeDiscoveryRepository) FindDiscoveryByUUID(uuid string) (*db.Discovery, error) {
	if f.findDiscovery != nil {
		return f.findDiscovery, nil
	}
	return nil, errors.New("fakeDiscoveryRepository: FindDiscoveryByUUID not configured for this test")
}

func (f *fakeDiscoveryRepository) CreateDiscovery(discovery *db.Discovery) error {
	return errors.New("fakeDiscoveryRepository: CreateDiscovery not configured for this test")
}

func (f *fakeDiscoveryRepository) DeleteDiscovery(discovery *db.Discovery) error {
	return errors.New("fakeDiscoveryRepository: DeleteDiscovery not configured for this test")
}

func (f *fakeDiscoveryRepository) UpdateDiscovery(discovery *db.Discovery) error {
	f.updateCalls = append(f.updateCalls, *discovery)
	return f.updateErr
}

func (f *fakeDiscoveryRepository) AssociateCertificatesToDiscovery(discovery *db.Discovery, certificates ...*db.Certificate) error {
	return errors.New("fakeDiscoveryRepository: AssociateCertificatesToDiscovery not configured for this test")
}

func (f *fakeDiscoveryRepository) List(pagination db.Pagination, discovery *db.Discovery) (*db.Pagination, error) {
	return nil, errors.New("fakeDiscoveryRepository: List not configured for this test")
}

// vaultLoginResponse is the envelope the Vault client needs in order to accept
// an AppRole login and store the returned token.
const vaultLoginResponse = `{"request_id":"stub","data":null,` +
	`"auth":{"client_token":"stub-token","policies":["default"],"lease_duration":3600,` +
	`"renewable":true,"token_type":"service","orphan":true}}`

// newVaultStub starts a server standing in for Vault. loginSucceeds decides
// whether the AppRole login is accepted; every other request is refused so
// that the error handling of the calling service runs.
func newVaultStub(t *testing.T, loginSucceeds bool) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if loginSucceeds && strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = w.Write([]byte(vaultLoginResponse))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	t.Cleanup(server.Close)

	return server
}

func newStubAuthority(url string) *db.AuthorityInstance {
	return &db.AuthorityInstance{
		UUID:           "authority-uuid",
		Name:           "authority-1",
		URL:            url,
		CredentialType: model.APPROLE_CRED,
		RoleId:         "role-id",
		RoleSecret:     "role-secret",
	}
}

func TestFailDiscoveryMarksAndPersistsTheDiscovery(t *testing.T) {
	repo := &fakeDiscoveryRepository{}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid"}

	service.failDiscovery(context.Background(), target, "vault refused the connection")

	if target.Status != "FAILED" {
		t.Errorf("status: got %q, want %q", target.Status, "FAILED")
	}
	if len(repo.updateCalls) != 1 {
		t.Fatalf("UpdateDiscovery calls: got %d, want 1", len(repo.updateCalls))
	}
}

func TestFailDiscoveryStillMarksTheDiscoveryWhenPersistingFails(t *testing.T) {
	repo := &fakeDiscoveryRepository{updateErr: errors.New("database unavailable")}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid"}

	service.failDiscovery(context.Background(), target, "vault refused the connection")

	if target.Status != "FAILED" {
		t.Errorf("status: got %q, want %q", target.Status, "FAILED")
	}
}

func TestDeleteDiscoveryReportsAFailedDelete(t *testing.T) {
	repo := &fakeDiscoveryRepository{findDiscovery: &db.Discovery{UUID: "discovery-uuid"}}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}

	response, err := service.DeleteDiscovery(context.Background(), "discovery-uuid")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusInternalServerError {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestDiscoveryCertificatesFailsWhenVaultRefusesTheLogin(t *testing.T) {
	stub := newVaultStub(t, false)
	repo := &fakeDiscoveryRepository{}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid"}

	service.DiscoveryCertificates(context.Background(), newStubAuthority(stub.URL), target, []string{"pki"})

	if target.Status != "FAILED" {
		t.Errorf("status: got %q, want %q", target.Status, "FAILED")
	}
}

func TestDiscoveryCertificatesCompletesWhenNoEnginesAreGiven(t *testing.T) {
	stub := newVaultStub(t, true)
	repo := &fakeDiscoveryRepository{}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid"}

	service.DiscoveryCertificates(context.Background(), newStubAuthority(stub.URL), target, nil)

	if target.Status != "COMPLETED" {
		t.Errorf("status: got %q, want %q", target.Status, "COMPLETED")
	}
}

func TestDiscoveryCertificatesReportsAnEngineThatCannotBeListed(t *testing.T) {
	stub := newVaultStub(t, true)
	repo := &fakeDiscoveryRepository{}
	service := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid"}

	service.DiscoveryCertificates(context.Background(), newStubAuthority(stub.URL), target, []string{"pki"})

	if len(repo.updateCalls) == 0 {
		t.Error("expected the discovery to be persisted")
	}
}

// fakeAuthorityRepository is an in-memory stand-in for
// *db.AuthorityRepository.
type fakeAuthorityRepository struct {
	findByUUID *db.AuthorityInstance
}

func (f *fakeAuthorityRepository) FindAuthorityInstanceByUUID(uuid string) (*db.AuthorityInstance, error) {
	if f.findByUUID != nil {
		return f.findByUUID, nil
	}
	return nil, errors.New("fakeAuthorityRepository: FindAuthorityInstanceByUUID not configured for this test")
}

func (f *fakeAuthorityRepository) ListAuthorityInstances() ([]*db.AuthorityInstance, error) {
	return nil, errors.New("fakeAuthorityRepository: ListAuthorityInstances not configured for this test")
}

func TestDiscoverCertificateReportsAnUnreachableVaultWhenNoEnginesAreGiven(t *testing.T) {
	stub := newVaultStub(t, false)
	discoveries := &fakeDiscoveryRepository{}
	authorities := &fakeAuthorityRepository{findByUUID: newStubAuthority(stub.URL)}
	service := &DiscoveryAPIService{discoveryRepo: discoveries, authorityRepo: authorities, log: zap.NewNop()}

	request := model.DiscoveryRequestDto{
		Name: "example-discovery",
		Attributes: []model.Attribute{
			model.DataAttribute{
				Uuid: model.DISCOVERY_AUTHORITY_ATTR,
				Content: []model.AttributeContent{
					model.ObjectAttributeContent{Data: map[string]any{"uuid": "authority-uuid"}},
				},
			},
		},
	}

	response, err := service.DiscoverCertificate(context.Background(), request)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusBadRequest)
	}
	if len(discoveries.updateCalls) == 0 {
		t.Error("expected the failed discovery to be persisted")
	}
}
