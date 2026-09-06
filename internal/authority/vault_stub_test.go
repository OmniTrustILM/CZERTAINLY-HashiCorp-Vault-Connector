package authority

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/db"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/model"
	"go.uber.org/zap"
)

// newVaultStub starts a server standing in for Vault. It answers the AppRole
// login so that vault.GetClient succeeds, and refuses every other request so
// that the error handling of the calling service runs. The refusal is a 403
// rather than a 500 because the Vault client retries server errors, which
// would add seconds of backoff to every test using the stub.
func newVaultStub(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = w.Write([]byte(`{"request_id":"stub","lease_id":"","renewable":false,` +
				`"lease_duration":0,"data":null,"wrap_info":null,"warnings":null,` +
				`"auth":{"client_token":"stub-token","accessor":"stub","policies":["default"],` +
				`"token_policies":["default"],"metadata":{},"lease_duration":3600,` +
				`"renewable":true,"entity_id":"","token_type":"service","orphan":true}}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	t.Cleanup(server.Close)

	return server
}

// newStubAuthority returns an authority that authenticates against the stub
// server at url with AppRole credentials.
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

// TestServicesReportVaultRejections drives every operation that reaches Vault
// past the connection step, so that the request path and its error handling
// both run against a Vault that refuses the call.
// selfSignedCertificateB64 returns a base64-encoded DER certificate, which the
// certificate operations decode before they reach Vault.
func selfSignedCertificateB64(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "certificate.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return base64.StdEncoding.EncodeToString(der)
}

// certificateRequestB64 returns a base64-encoded DER certificate request, in
// the form the issue and renew operations expect.
func certificateRequestB64(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "request.example.com"}}, key)
	if err != nil {
		t.Fatalf("create certificate request: %v", err)
	}

	return base64.StdEncoding.EncodeToString(csr)
}

func TestServicesReportVaultRejections(t *testing.T) {
	stub := newVaultStub(t)
	certificate := selfSignedCertificateB64(t)
	request := certificateRequestB64(t)
	attributes := []model.Attribute{
		engineAttribute(map[string]any{"engineName": "pki"}),
		roleAttribute("web"),
	}

	newRepo := func() *fakeAuthorityRepository {
		return &fakeAuthorityRepository{findByUUID: newStubAuthority(stub.URL)}
	}
	authorityService := &AuthorityManagementAPIService{authorityRepo: newRepo(), log: zap.NewNop()}
	certificateService := &CertificateManagementAPIService{authorityRepo: newRepo(), log: zap.NewNop()}

	operations := map[string]func() (model.ImplResponse, error){
		"get CA certificates": func() (model.ImplResponse, error) {
			return authorityService.GetCaCertificates(context.Background(), "authority-uuid", model.CaCertificatesRequestDto{
				RaProfileAttributes: attributes,
			})
		},
		"get CRL": func() (model.ImplResponse, error) {
			return authorityService.GetCrl(context.Background(), "authority-uuid", model.CertificateRevocationListRequestDto{
				RaProfileAttributes: attributes,
			})
		},
		"get delta CRL": func() (model.ImplResponse, error) {
			return authorityService.GetCrl(context.Background(), "authority-uuid", model.CertificateRevocationListRequestDto{
				RaProfileAttributes: attributes,
				Delta:               true,
			})
		},
		"RA profile callback": func() (model.ImplResponse, error) {
			return authorityService.RAProfileCallback(context.Background(), "authority-uuid", "pki")
		},
		"identify certificate": func() (model.ImplResponse, error) {
			return certificateService.IdentifyCertificate(context.Background(), "authority-uuid", model.CertificateIdentificationRequestDto{
				RaProfileAttributes: attributes,
				Certificate:         certificate,
			})
		},
		"issue certificate": func() (model.ImplResponse, error) {
			return certificateService.IssueCertificate(context.Background(), "authority-uuid", model.CertificateSignRequestDto{
				CertificateRequestFormat: model.CERTIFICATEREQUESTFORMAT_PKCS10,
				RaProfileAttributes:      attributes,
				Request:                  request,
			})
		},
		"revoke certificate": func() (model.ImplResponse, error) {
			return certificateService.RevokeCertificate(context.Background(), "authority-uuid", model.CertRevocationDto{
				RaProfileAttributes: attributes,
				Certificate:         certificate,
			})
		},
	}

	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			response, _ := operation()

			if response.Code < http.StatusBadRequest {
				t.Errorf("code: got %d, want a client or server error", response.Code)
			}
		})
	}
}

func TestListRAProfileAttributesReportsAVaultThatCannotListMounts(t *testing.T) {
	stub := newVaultStub(t)
	repo := &fakeAuthorityRepository{findByUUID: newStubAuthority(stub.URL)}
	service := &AuthorityManagementAPIService{authorityRepo: repo, log: zap.NewNop()}

	response, err := service.ListRAProfileAttributes(context.Background(), "authority-uuid")

	if response.Code != http.StatusInternalServerError {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if err == nil {
		t.Error("expected the listing error to be returned alongside the response")
	}
}
